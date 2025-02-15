use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

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
            if let Ok(mut pool) = crate::events::thread_pool::THREAD_POOL.lock() {
                pool.keep_alive = Duration::from_secs(seconds);
            }
        }
    }
}

pub fn handle_thread_pool_max_threads(_ctx: &mut ConfigContext, config: &Value) {
    if let Some(max_threads) = get_config_param(config, 0) {
        if let Ok(count) = max_threads.parse::<usize>() {
            if let Ok(mut pool) = crate::events::thread_pool::THREAD_POOL.lock() {
                println!("Setting thread pool max threads: {}", count);
                pool.max_threads = count;
            }
        }
    }
}

pub fn handle_thread_pool_max_queue_size(_ctx: &mut ConfigContext, config: &Value) {
    if let Some(max_queue_size) = get_config_param(config, 0) {
        if let Ok(size) = max_queue_size.parse::<usize>() {
            if let Ok(mut pool) = crate::events::thread_pool::THREAD_POOL.lock() {
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
    pub max_queue_size: usize, // 0 則為無界
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

struct Worker {
    last_active: Instant,
    thread: Option<thread::JoinHandle<()>>,
}

pub struct ThreadPool {
    tasks: Arc<(Mutex<VecDeque<Task>>, Condvar)>,
    workers: Arc<Mutex<Vec<Worker>>>,
    keep_alive: Duration,
    max_threads: usize,
    max_queue_size: usize,
}

impl ThreadPool {
    pub fn new(config: ThreadPoolConfig) -> Self {
        Self {
            tasks: Arc::new((Mutex::new(VecDeque::new()), Condvar::new())),
            workers: Arc::new(Mutex::new(Vec::new())),
            keep_alive: config.keep_alive,
            max_threads: config.max_threads,
            max_queue_size: config.max_queue_size,
        }
    }

    pub fn spawn<F>(&self, f: F) -> Result<(), ThreadPoolError>
    where
        F: FnOnce() + Send + 'static,
    {
        let task = Box::new(f);
        let (lock, cvar) = &*self.tasks;
        let mut queue = lock.lock().unwrap();
        if queue.len() >= self.max_queue_size {
            return Err(ThreadPoolError::QueueFull);
        }
        queue.push_back(task);
        let task_count = queue.len();
        drop(queue);

        let mut workers_guard = self.workers.lock().unwrap();
        workers_guard.retain(|w| w.thread.is_some());
        let active_count = workers_guard.len();
        if task_count > active_count && active_count < self.max_threads {
            drop(workers_guard);
            self.spawn_worker();
        } else {
            drop(workers_guard);
        }

        cvar.notify_one();

        Ok(())
    }

    pub fn spawn_worker(&self) {
        let workers = Arc::clone(&self.workers);
        let tasks = Arc::clone(&self.tasks);
        let keep_alive = self.keep_alive;

        let worker_id = {
            let mut workers = workers.lock().unwrap();
            let id = workers.len();
            workers.push(Worker {
                last_active: Instant::now(),
                thread: None,
            });
            id
        };

        let thread = thread::spawn(move || {
            let (lock, cvar) = &*tasks;

            loop {
                let queue = lock.lock().unwrap();

                let result = cvar
                    .wait_timeout_while(queue, keep_alive, |queue| queue.is_empty())
                    .unwrap();

                let (mut queue, timeout) = result;

                if timeout.timed_out() && queue.is_empty() {
                    let mut workers = workers.lock().unwrap();
                    if let Some(worker) = workers.get_mut(worker_id) {
                        worker.thread = None;
                    }
                    break;
                }

                if let Some(task) = queue.pop_front() {
                    let mut workers = workers.lock().unwrap();
                    if let Some(worker) = workers.get_mut(worker_id) {
                        worker.last_active = Instant::now();
                    }
                    drop(queue);

                    task();
                }
            }
        });

        let mut workers = self.workers.lock().unwrap();
        if let Some(worker) = workers.get_mut(worker_id) {
            worker.thread = Some(thread);
        }
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        if let Ok(mut workers) = self.workers.lock() {
            for worker in workers.iter_mut() {
                if let Some(thread) = worker.thread.take() {
                    thread.join().unwrap();
                }
            }
        }
    }
}
