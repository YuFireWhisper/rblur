use std::{
    any::TypeId,
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use crate::{
    core::config::{
        command::Command, config_context::ConfigContext, config_file_parser::ConfigFileParser,
    },
    events::thread_pool::THREAD_POOL,
    register_commands,
};

use super::{
    get_context_u8,
    http_location::{HttpLocation, HttpLocationContext},
    http_manager::HttpContext,
    http_response::HttpResponse,
    http_type::HttpVersion,
};

register_commands!(
    Command::new(
        "listen",
        vec![TypeId::of::<HttpContext>()],
        handle_set_listen
    ),
    Command::new(
        "server_name",
        vec![TypeId::of::<HttpContext>()],
        handle_set_server_name
    )
);

pub fn handle_create_server(ctx: &mut ConfigContext) {
    let prev_ctx = ctx.current_ctx.take();
    let prev_block_type_id = ctx.current_block_type_id.take();

    let mut server_ctx = Box::new(HttpServerContext::new());
    ctx.current_ctx = Some(get_context_u8(&mut *server_ctx));
    ctx.current_block_type_id = Some(TypeId::of::<HttpServerContext>());

    {
        let mut parser = ConfigFileParser::instance().lock().unwrap();
        parser.parse(ctx).unwrap();
    }

    let listen_addr = server_ctx.listen.clone();
    let server_ctx = Arc::new(*server_ctx);

    ctx.current_ctx = prev_ctx;
    ctx.current_block_type_id = prev_block_type_id;

    if let Some(http_ctx_ptr) = &ctx.current_ctx {
        let http_ptr = http_ctx_ptr.load(Ordering::SeqCst);
        let http_ctx = unsafe { &mut *(http_ptr as *mut HttpContext) };

        http_ctx.set_server(&listen_addr, server_ctx);
    }
}

pub fn handle_set_listen(ctx: &mut ConfigContext) {
    let listen = &ctx.current_cmd_args[0];
    if let Some(srv_ctx_ptr) = &ctx.current_ctx {
        let srv_ptr = srv_ctx_ptr.load(Ordering::SeqCst);
        if !srv_ptr.is_null() {
            let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };
            srv_ctx.listen = listen.into();
        }
    }
}

pub fn handle_set_server_name(ctx: &mut ConfigContext) {
    let server_name = &ctx.current_cmd_args[0];
    if let Some(srv_ctx_ptr) = &ctx.current_ctx {
        let srv_ptr = srv_ctx_ptr.load(Ordering::SeqCst);
        let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };
        srv_ctx.server_name.push(server_name.into());
    }
}

#[derive(Default, Clone)]
pub struct HttpServerContext {
    listen: String,
    server_name: Vec<String>,
    locations: HashMap<String, *mut u8>,
}

impl HttpServerContext {
    pub fn new() -> Self {
        Self {
            listen: "127.0.0.1:8080".to_string(),
            server_name: Vec::new(),
            locations: HashMap::new(),
        }
    }

    pub fn set_location(&mut self, path: &str, ctx: *mut u8) {
        self.locations.insert(path.to_string(), ctx);
    }

    pub fn find_server_name(&self, server_name: &str) -> Option<Arc<HttpServerContext>> {
        if self.server_name.contains(&server_name.to_string()) {
            return Some(Arc::new(self.clone()));
        }
        None
    }
}

static RUNNING: AtomicBool = AtomicBool::new(true);

pub struct HttpServer {
    listener: TcpListener,
    ctx: Arc<HttpServerContext>,
    location: Option<HttpLocation>,
}

impl HttpServer {
    pub fn new(ctx: &Arc<HttpServerContext>) -> Self {
        let location = ctx
            .locations
            .iter()
            .next()
            .map(|(_, &ptr)| unsafe { &*(ptr as *const HttpLocationContext) })
            .map(|ctx| HttpLocation::new(ctx.clone()));

        Self {
            listener: TcpListener::bind(&ctx.listen).unwrap(),
            ctx: ctx.clone(),
            location,
        }
    }

    pub fn start(self) -> thread::JoinHandle<()> {
        println!("Server listening on {}", self.ctx.listen);

        thread::spawn(move || {
            self.listener.set_nonblocking(true).unwrap();

            let location = match self.location {
                Some(location) => location,
                None => {
                    eprintln!("No location context found for server");
                    return;
                }
            };

            while RUNNING.load(Ordering::SeqCst) {
                match self.listener.incoming().next() {
                    Some(Ok(stream)) => {
                        let mut stream = stream;
                        let location = location.clone();

                        if let Ok(pool) = THREAD_POOL.lock() {
                            if let Err(e) = pool.spawn(move || {
                                if let Err(e) = handle_connection(&mut stream, &location) {
                                    eprintln!("Error handling connection: {}", e);
                                }
                            }) {
                                eprintln!("Thread pool error: {}", e);
                            }
                        }
                    }
                    Some(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Some(Err(e)) => eprintln!("Connection failed: {}", e),
                    None => break,
                }
            }
        })
    }
}

fn handle_connection(stream: &mut TcpStream, location: &HttpLocation) -> std::io::Result<()> {
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer)?;
    if n == 0 {
        return Ok(()); // 連接已關閉
    }

    let request = String::from_utf8_lossy(&buffer);
    let path = parse_request_path(&request);

    let response = if path == location.ctx.path {
        location.handle(1).unwrap_or_else(create_404_response)
    } else {
        create_404_response()
    };

    let response_string = format!(
        "{}\r\n{}{}",
        response.status_line, response.header, response.body
    );

    stream.write_all(response_string.as_bytes())?;
    stream.flush()?;

    Ok(())
}

fn parse_request_path(request: &str) -> &str {
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
}

fn create_404_response() -> HttpResponse {
    let mut response = HttpResponse::new();
    response.set_status_line(HttpVersion::Http1_1, 404);
    response.set_header("Content-Type", "text/plain");
    response.set_body("404 Not Found");
    response
}
