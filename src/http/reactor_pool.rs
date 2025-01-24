use std::{
    io::{self, Read, Write},
    net::TcpStream,
    os::fd::{AsRawFd, RawFd},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use std::sync::mpsc::{channel, Receiver, Sender};

use crate::events::{
    poll::{EventHandler, EventType, Poll},
    thread_pool::{ThreadPool, ThreadPoolConfig},
};

use super::{
    http_request::HttpRequest,
    http_response::HttpResponse,
    http_router::Router,
    http_type::HttpVersion,
};

pub struct ReactorPoolConfig {
    pub reactor_count: usize,
    pub poll_timeout: Duration,
    pub static_files_dir: PathBuf,
}

impl Default for ReactorPoolConfig {
    fn default() -> Self {
        Self {
            reactor_count: thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            poll_timeout: Duration::from_millis(100),
            static_files_dir: PathBuf::from("static"),
        }
    }
}

enum ReactorMessage {
    RegisterStream(TcpStream),
    Shutdown,
}

pub struct Reactor {
    poll: Poll,
    router: Arc<Router>,
    thread_pool: Arc<ThreadPool>,
    receiver: Receiver<ReactorMessage>,
    static_files_dir: PathBuf,
}

impl Reactor {
    fn new(
        router: Arc<Router>,
        thread_pool: Arc<ThreadPool>,
        receiver: Receiver<ReactorMessage>,
        static_files_dir: PathBuf,
    ) -> io::Result<Self> {
        Ok(Self {
            poll: Poll::new()?,
            router,
            thread_pool,
            receiver,
            static_files_dir,
        })
    }

    fn run(&mut self) -> io::Result<()> {
        loop {
            self.process_messages()?;
            self.poll.poll(Some(Duration::from_millis(100)))?;
        }
    }

    fn process_messages(&mut self) -> io::Result<()> {
        while let Ok(msg) = self.receiver.try_recv() {
            match msg {
                ReactorMessage::RegisterStream(stream) => self.register_stream(stream)?,
                ReactorMessage::Shutdown => return Ok(()),
            }
        }
        Ok(())
    }

    fn register_stream(&mut self, stream: TcpStream) -> io::Result<()> {
        let fd = stream.as_raw_fd();
        let stream = Arc::new(Mutex::new(stream));
        
        let handler = ReactorHandler {
            stream: Arc::clone(&stream),
            router: Arc::clone(&self.router),
            thread_pool: Arc::clone(&self.thread_pool),
            static_files_dir: self.static_files_dir.clone(),
        };

        self.poll.register_handler(fd, EventType::Read, Box::new(handler))?;
        Ok(())
    }
}

struct ReactorHandler {
    stream: Arc<Mutex<TcpStream>>,
    router: Arc<Router>,
    thread_pool: Arc<ThreadPool>,
    static_files_dir: PathBuf,
}

impl ReactorHandler {
    fn get_content_type(path: &str) -> &'static str {
        path.split('.')
            .last()
            .map(|ext| match ext.to_lowercase().as_str() {
                "html" => "text/html",
                "css" => "text/css",
                "js" => "application/javascript",
                "jpg" | "jpeg" => "image/jpeg",
                "png" => "image/png",
                "gif" => "image/gif",
                "svg" => "image/svg+xml",
                "json" => "application/json",
                "txt" => "text/plain",
                _ => "application/octet-stream",
            })
            .unwrap_or("application/octet-stream")
    }

    fn read_static_file(&self, path: &str) -> io::Result<(Vec<u8>, &'static str)> {
        let file_path = self.static_files_dir.join(path.trim_start_matches('/'));
        let content = std::fs::read(&file_path)?;
        let content_type = Self::get_content_type(path);
        Ok((content, content_type))
    }

    fn read_request(stream: &mut TcpStream) -> io::Result<HttpRequest> {
        let mut request = HttpRequest::new();
        let mut buffer = [0; 1024];

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = request.parse(&buffer[..n]) {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                    }
                    if request.is_complete() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        Ok(request)
    }

    fn handle_request(&self, request: &HttpRequest) -> io::Result<HttpResponse> {
        let mut response = HttpResponse::new();
        
        if let Some(()) = self.router.route(request.path()) {
            match self.read_static_file(request.path()) {
                Ok((content, content_type)) => {
                    response.set_status_line(HttpVersion::Http1_1, 200);
                    response.set_header("Content-Type", content_type);
                    response.set_header("Content-Length", &content.len().to_string());
                    response.set_body(&String::from_utf8_lossy(&content));
                }
                Err(_) => {
                    response.set_status_line(HttpVersion::Http1_1, 404);
                    response.set_header("Content-Type", "text/plain");
                    response.set_body("404 Not Found");
                }
            }
        } else {
            response.set_status_line(HttpVersion::Http1_1, 404);
            response.set_header("Content-Type", "text/plain");
            response.set_body("404 Not Found");
        }

        Ok(response)
    }

    fn process_connection(stream: &mut TcpStream, handler: &ReactorHandler) -> io::Result<()> {
        let request = Self::read_request(stream)?;
        if request.is_complete() {
            let response = handler.handle_request(&request)?;
            let response_str = format!(
                "{}\r\n{}{}",
                response.status_line,
                response.header,
                response.body
            );
            stream.write_all(response_str.as_bytes())?;
        }
        Ok(())
    }
}

impl EventHandler for ReactorHandler {
    fn handle(&self, _fd: RawFd, event_type: EventType) -> io::Result<()> {
        if event_type != EventType::Read {
            return Ok(());
        }

        let stream = Arc::clone(&self.stream);
        let handler = self.clone();

        if let Err(e) = self.thread_pool.spawn(move || {
            if let Ok(mut stream) = stream.lock() {
                if let Err(e) = Self::process_connection(&mut stream, &handler) {
                    eprintln!("Error processing connection: {}", e);
                }
            }
        }) {
            eprintln!("Failed to spawn thread: {}", e);
        }

        Ok(())
    }
}

impl Clone for ReactorHandler {
    fn clone(&self) -> Self {
        Self {
            stream: Arc::clone(&self.stream),
            router: Arc::clone(&self.router),
            thread_pool: Arc::clone(&self.thread_pool),
            static_files_dir: self.static_files_dir.clone(),
        }
    }
}

pub struct ReactorPool {
    reactors: Vec<(Arc<Mutex<()>>, Sender<ReactorMessage>)>,
    current: Arc<Mutex<usize>>,
    handles: Vec<JoinHandle<io::Result<()>>>,
}

impl ReactorPool {
    pub fn new(config: ReactorPoolConfig, router: Router) -> io::Result<Self> {
        let router = Arc::new(router);
        let current = Arc::new(Mutex::new(0));
        let mut reactors = Vec::with_capacity(config.reactor_count);
        let mut handles = Vec::with_capacity(config.reactor_count);

        let thread_pool = Arc::new(ThreadPool::new(ThreadPoolConfig {
            keep_alive: Duration::from_secs(60),
            max_threads: config.reactor_count * 4,
            max_queue_size: 1000,
        }));

        for _ in 0..config.reactor_count {
            let (sender, receiver) = channel();
            let mut reactor = Reactor::new(
                Arc::clone(&router),
                Arc::clone(&thread_pool),
                receiver,
                config.static_files_dir.clone(),
            )?;

            let handle = thread::spawn(move || reactor.run());

            reactors.push((Arc::new(Mutex::new(())), sender));
            handles.push(handle);
        }

        Ok(Self {
            reactors,
            current,
            handles,
        })
    }

    pub fn accept_connection(&self, stream: TcpStream) -> io::Result<()> {
        let mut current = self.current.lock().unwrap();
        *current = (*current + 1) % self.reactors.len();
        let reactor_id = *current;
        drop(current);

        stream.set_nonblocking(true)?;

        let (_lock, sender) = &self.reactors[reactor_id];
        sender
            .send(ReactorMessage::RegisterStream(stream))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(())
    }
}

impl Drop for ReactorPool {
    fn drop(&mut self) {
        for handle in self.handles.drain(..) {
            if let Ok(Err(e)) = handle.join() {
                eprintln!("Reactor error: {}", e);
            }
        }
    }
}
