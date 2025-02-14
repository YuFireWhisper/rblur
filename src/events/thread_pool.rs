use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

use once_cell::sync::Lazy;
use thiserror::Error;

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

pub static THREAD_POOL: Lazy<Mutex<ThreadPool>> =
    Lazy::new(|| Mutex::new(ThreadPool::new(ThreadPoolConfig::new())));

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
