use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

pub enum ThreadPoolError {
    QueueFull,
}

pub struct ThreadPoolConfig {
    keep_alive: Duration,
    max_threads: usize,
    max_queue_size: usize, // 0 則為無界
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

        let workers = self.workers.lock().unwrap();
        if queue.len() > workers.len() && workers.len() < self.max_threads {
            drop(workers);
            self.spawn_worker();
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
