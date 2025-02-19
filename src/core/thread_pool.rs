use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use crossbeam_channel::{bounded, unbounded, Receiver, RecvTimeoutError, Sender, TrySendError};
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
                let mut ka = pool.keep_alive.lock().unwrap();
                *ka = Duration::from_secs(seconds);
            }
        }
    }
}

pub fn handle_thread_pool_max_threads(_ctx: &mut ConfigContext, config: &Value) {
    if let Some(max_threads) = get_config_param(config, 0) {
        if let Ok(count) = max_threads.parse::<usize>() {
            if let Ok(pool) = THREAD_POOL.lock() {
                pool.max_threads.store(count, Ordering::Relaxed);
            }
        }
    }
}

pub fn handle_thread_pool_max_queue_size(_ctx: &mut ConfigContext, config: &Value) {
    if let Some(max_queue_size) = get_config_param(config, 0) {
        if let Ok(size) = max_queue_size.parse::<usize>() {
            if let Ok(pool) = THREAD_POOL.lock() {
                pool.max_queue_size.store(size, Ordering::Relaxed);
            }
        }
    }
}

pub static THREAD_POOL: Lazy<Mutex<ThreadPool>> = Lazy::new(|| {
    let config = ThreadPoolConfig::new();
    Mutex::new(ThreadPool::new(config))
});

#[derive(Debug, Error)]
pub enum ThreadPoolError {
    #[error("Thread pool task queue is full")]
    QueueFull,
}

pub struct ThreadPoolConfig {
    keep_alive: Duration,
    max_threads: usize,
    max_queue_size: usize,
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
    active_threads: Arc<AtomicUsize>,
    max_threads: Arc<AtomicUsize>,
    keep_alive: Arc<Mutex<Duration>>,
    max_queue_size: Arc<AtomicUsize>,
    handles: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
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
            active_threads: Arc::new(AtomicUsize::new(0)),
            max_threads: Arc::new(AtomicUsize::new(config.max_threads)),
            keep_alive: Arc::new(Mutex::new(config.keep_alive)),
            max_queue_size: Arc::new(AtomicUsize::new(config.max_queue_size)),
            handles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn spawn<F>(&self, f: F) -> Result<(), ThreadPoolError>
    where
        F: FnOnce() + Send + 'static,
    {
        let task = Box::new(f);

        let current_max_queue_size = self.max_queue_size.load(Ordering::Relaxed);
        if current_max_queue_size > 0 {
            if let Err(TrySendError::Full(_)) = self.sender.try_send(task) {
                return Err(ThreadPoolError::QueueFull);
            }
        } else {
            self.sender
                .send(task)
                .map_err(|_| ThreadPoolError::QueueFull)?;
        }

        let current_max_threads = self.max_threads.load(Ordering::Relaxed);
        loop {
            let current_active = self.active_threads.load(Ordering::Relaxed);
            if current_active >= current_max_threads {
                break;
            }

            if self
                .active_threads
                .compare_exchange_weak(
                    current_active,
                    current_active + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                let receiver = self.receiver.clone();
                let keep_alive = *self.keep_alive.lock().unwrap();
                let active_threads = self.active_threads.clone();
                let handles = self.handles.clone();

                let handle = thread::spawn(move || loop {
                    match receiver.recv_timeout(keep_alive) {
                        Ok(task) => {
                            task();
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            active_threads.fetch_sub(1, Ordering::AcqRel);
                            break;
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            active_threads.fetch_sub(1, Ordering::AcqRel);
                            break;
                        }
                    }
                });

                handles.lock().unwrap().push(handle);
                break;
            }
        }

        Ok(())
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        let mut handles = self.handles.lock().unwrap();
        for handle in handles.drain(..) {
            let _ = handle.join();
        }
    }
}
