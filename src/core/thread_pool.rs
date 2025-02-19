use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use crossbeam_channel::{bounded, unbounded, Receiver, RecvTimeoutError, Sender};
use once_cell::sync::Lazy;
use thiserror::Error;

use crate::{
    core::config::{
        command::{CommandBuilder, ParameterBuilder},
        config_context::ConfigContext,
        config_manager::get_config_param,
    },
    register_commands,
};
use serde_json::Value;

register_commands!(
    CommandBuilder::new("thread_pool_keep_alive")
        .allowed_parents(vec!["other".to_string()])
        .display_name("en", "Thread Pool Keep Alive")
        .display_name("zh-tw", "執行緒池保活時間")
        .desc(
            "en",
            "Sets the keep-alive duration for idle threads in the thread pool"
        )
        .desc("zh-tw", "設置執行緒池中閒置執行緒的保活時間")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Duration (seconds)")
            .display_name("zh-tw", "時間 (秒)")
            .type_name("usize")
            .is_required(true)
            .default("30")
            .desc(
                "en",
                "Duration in seconds for how long idle threads should be kept alive"
            )
            .desc("zh-tw", "閒置執行緒應該保持活動的時間(秒)")
            .build()])
        .build(handle_thread_pool_keep_alive),
    CommandBuilder::new("thread_pool_max_threads")
        .allowed_parents(vec!["other".to_string()])
        .display_name("en", "Thread Pool Maximum Threads")
        .display_name("zh-tw", "執行緒池最大執行緒數")
        .desc(
            "en",
            "Sets the maximum number of threads in the thread pool"
        )
        .desc("zh-tw", "設置執行緒池中的最大執行緒數量")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Thread Count")
            .display_name("zh-tw", "執行緒數量")
            .type_name("usize")
            .is_required(true)
            .default("8")
            .desc("en", "Maximum number of threads that can exist in the pool")
            .desc("zh-tw", "池中可以存在的最大執行緒數量")
            .build()])
        .build(handle_thread_pool_max_threads),
    CommandBuilder::new("thread_pool_max_queue_size")
        .allowed_parents(vec!["other".to_string()])
        .display_name("en", "Thread Pool Maximum Queue Size")
        .display_name("zh-tw", "執行緒池最大佇列大小")
        .desc(
            "en",
            "Sets the maximum size of the task queue in the thread pool"
        )
        .desc("zh-tw", "設置執行緒池中任務佇列的最大大小")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Queue Size")
            .display_name("zh-tw", "佇列大小")
            .type_name("usize")
            .is_required(true)
            .default("10000")
            .desc(
                "en",
                "Maximum number of tasks that can be queued (0 for unbounded)"
            )
            .desc("zh-tw", "可以排隊的最大任務數量 (0表示無限制)")
            .build()])
        .build(handle_thread_pool_max_queue_size)
);

pub fn handle_thread_pool_keep_alive(_ctx: &mut ConfigContext, config: &Value) {
    if let Some(keep_alive) = get_config_param(config, 0) {
        if let Ok(seconds) = keep_alive.parse::<u64>() {
            if let Ok(pool) = THREAD_POOL.lock() {
                pool.keep_alive.store(seconds, Ordering::Relaxed);
            }
        }
    }
}

pub fn handle_thread_pool_max_threads(_ctx: &mut ConfigContext, config: &Value) {
    if let Some(max_threads) = get_config_param(config, 0) {
        if let Ok(count) = max_threads.parse::<usize>() {
            if let Ok(pool) = THREAD_POOL.lock() {
                println!("Setting thread pool max threads: {}", count);
                pool.max_threads.store(count, Ordering::Relaxed);
            }
        }
    }
}

pub fn handle_thread_pool_max_queue_size(_ctx: &mut ConfigContext, config: &Value) {
    if let Some(max_queue_size) = get_config_param(config, 0) {
        if let Ok(size) = max_queue_size.parse::<usize>() {
            if let Ok(mut pool) = THREAD_POOL.lock() {
                pool.max_queue_size = size;
            }
        }
    }
}

pub static THREAD_POOL: Lazy<Mutex<ThreadPool>> =
    Lazy::new(|| Mutex::new(ThreadPool::new(ThreadPoolConfig::new())));

#[derive(Debug, Error)]
pub enum ThreadPoolError {
    #[error("Thread pool task queue is full")]
    QueueFull,
}

pub struct ThreadPoolConfig {
    pub keep_alive: Duration,
    pub max_threads: usize,
    pub max_queue_size: usize, // 0 表示無界
}

impl Default for ThreadPoolConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadPoolConfig {
    pub fn new() -> Self {
        Self {
            keep_alive: Duration::from_secs(30),
            max_threads: std::thread::available_parallelism()
                .map(|n| n.get() * 2)
                .unwrap_or(8),
            max_queue_size: 10000,
        }
    }
}

type Task = Box<dyn FnOnce() + Send + 'static>;

pub struct ThreadPool {
    sender: Sender<Task>,
    receiver: Receiver<Task>,
    workers: Mutex<Vec<thread::JoinHandle<()>>>,
    worker_count: Arc<AtomicUsize>,
    pub keep_alive: Arc<AtomicU64>,
    pub max_threads: AtomicUsize,
    pub max_queue_size: usize,
}

impl ThreadPool {
    pub fn new(config: ThreadPoolConfig) -> Self {
        let (sender, receiver) = if config.max_queue_size == 0 {
            unbounded()
        } else {
            bounded(config.max_queue_size)
        };

        Self {
            sender,
            receiver,
            workers: Mutex::new(Vec::new()),
            worker_count: Arc::new(AtomicUsize::new(0)),
            keep_alive: Arc::new(AtomicU64::new(config.keep_alive.as_secs())),
            max_threads: AtomicUsize::new(config.max_threads),
            max_queue_size: config.max_queue_size,
        }
    }

    pub fn spawn<F>(&self, f: F) -> Result<(), ThreadPoolError>
    where
        F: FnOnce() + Send + 'static,
    {
        let task = Box::new(f);
        self.sender.try_send(task).map_err(|err| {
            if err.is_full() {
                ThreadPoolError::QueueFull
            } else {
                // 其他錯誤一併回傳 QueueFull
                ThreadPoolError::QueueFull
            }
        })?;

        let queued = self.receiver.len();
        let current_workers = self.worker_count.load(Ordering::Acquire);
        let max_threads = self.max_threads.load(Ordering::Acquire);
        if queued > current_workers && current_workers < max_threads {
            self.spawn_worker();
        }
        Ok(())
    }

    fn spawn_worker(&self) {
        let max_threads = self.max_threads.load(Ordering::Acquire);
        let current = self.worker_count.fetch_add(1, Ordering::AcqRel);
        if current >= max_threads {
            self.worker_count.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        let receiver = self.receiver.clone();
        let keep_alive = Arc::clone(&self.keep_alive);
        let worker_count = Arc::clone(&self.worker_count);
        let handle = thread::spawn(move || loop {
            let timeout = Duration::from_secs(keep_alive.load(Ordering::Relaxed));
            match receiver.recv_timeout(timeout) {
                Ok(task) => {
                    task();
                }
                Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {
                    worker_count.fetch_sub(1, Ordering::AcqRel);
                    break;
                }
            }
        });
        self.workers.lock().unwrap().push(handle);
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        let mut workers = self.workers.lock().unwrap();
        while let Some(handle) = workers.pop() {
            let _ = handle.join();
        }
    }
}
