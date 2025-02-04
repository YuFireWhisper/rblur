use rustls::pki_types::pem::PemObject;
use std::{
    any::TypeId,
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, AtomicPtr, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig, ServerConnection,
};

use crate::{
    core::config::{
        command::Command, config_context::ConfigContext, config_file_parser::parse_context_of,
    },
    events::thread_pool::THREAD_POOL,
    http::http_ssl::HttpSSL,
    register_commands,
};

use super::{
    get_context_u8,
    http_location::{HttpLocation, HttpLocationContext},
    http_manager::HttpContext,
    http_response::HttpResponse,
    http_ssl::HttpSSLContext,
    http_type::HttpVersion,
};

register_commands!(
    Command::new(
        "server",
        vec![TypeId::of::<HttpContext>()],
        handle_create_server,
    ),
    Command::new(
        "listen",
        vec![TypeId::of::<HttpServerContext>()],
        handle_set_listen
    ),
    Command::new(
        "server_name",
        vec![TypeId::of::<HttpServerContext>()],
        handle_set_server_name
    ),
);

pub fn handle_create_server(ctx: &mut ConfigContext) {
    let prev_ctx = ctx.current_ctx.take();
    let prev_block_type_id = ctx.current_block_type_id.take();

    let mut server_ctx = HttpServerContext::new();
    ctx.current_ctx = Some(get_context_u8(&mut server_ctx));
    ctx.current_block_type_id = Some(TypeId::of::<HttpServerContext>());

    parse_context_of(ctx).unwrap();

    let listen_addr = server_ctx.listen().to_string();
    let server_ctx = Arc::new(server_ctx);

    ctx.current_ctx = prev_ctx;
    ctx.current_block_type_id = prev_block_type_id;

    if let Some(http_ctx_ptr) = &ctx.current_ctx {
        let http_ptr = http_ctx_ptr.load(Ordering::SeqCst);
        let http_ctx = unsafe { &mut *(http_ptr as *mut HttpContext) };
        http_ctx.set_server(&listen_addr, server_ctx);
    }
}

pub fn handle_set_listen(ctx: &mut ConfigContext) {
    let listen = &ctx.current_cmd_args[1];
    if let Some(srv_ctx_ptr) = &ctx.current_ctx {
        let srv_ptr = srv_ctx_ptr.load(Ordering::SeqCst);
        if !srv_ptr.is_null() {
            let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };
            srv_ctx.set_listen(listen);
        }
    }
}

pub fn handle_set_server_name(ctx: &mut ConfigContext) {
    let server_name = &ctx.current_cmd_args[1];
    if let Some(srv_ctx_ptr) = &ctx.current_ctx {
        let srv_ptr = srv_ctx_ptr.load(Ordering::SeqCst);
        let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };
        srv_ctx.add_server_name(server_name);
    }
}

pub fn get_server_ctx(current_ctx: &Option<AtomicPtr<u8>>) -> Option<&mut HttpServerContext> {
    if let Some(srv_ctx_ptr) = current_ctx {
        let srv_ptr = srv_ctx_ptr.load(Ordering::SeqCst);
        return Some(unsafe { &mut *(srv_ptr as *mut HttpServerContext) });
    }

    None
}

#[derive(Default)]
pub struct HttpServerContext {
    listen: Mutex<String>,
    server_names: Mutex<Vec<String>>,
    http_version: Mutex<HttpVersion>,
    locations: Mutex<HashMap<String, Arc<HttpLocationContext>>>,
    ssl: Mutex<Option<HttpSSLContext>>,
}

impl HttpServerContext {
    pub fn new() -> Self {
        Self {
            listen: Mutex::new("127.0.0.1:8080".to_string()),
            server_names: Mutex::new(Vec::new()),
            locations: Mutex::new(HashMap::new()),
            http_version: Mutex::new(HttpVersion::default()),
            ssl: Mutex::new(None),
        }
    }

    pub fn set_listen(&self, addr: &str) {
        if let Ok(mut listen) = self.listen.lock() {
            *listen = addr.to_string();
        }
    }

    pub fn listen(&self) -> String {
        self.listen.lock().unwrap().clone()
    }

    pub fn add_server_name(&self, name: &str) {
        if let Ok(mut names) = self.server_names.lock() {
            names.push(name.to_string());
        }
    }

    pub fn set_location(&self, path: &str, ctx: *mut u8) {
        if let Ok(mut locations) = self.locations.lock() {
            let location_ctx = unsafe { &*(ctx as *const HttpLocationContext) };
            locations.insert(path.to_string(), Arc::new(location_ctx.clone()));
        }
    }

    pub fn get_locations(&self) -> Vec<(String, Arc<HttpLocationContext>)> {
        self.locations
            .lock()
            .map(|locations| {
                locations
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn find_server_name(&self, server_name: &str) -> Option<bool> {
        self.server_names
            .lock()
            .ok()
            .map(|names| names.contains(&server_name.to_string()))
    }

    pub fn set_http_version(&self, version: HttpVersion) {
        if let Ok(mut v) = self.http_version.lock() {
            *v = version;
        }
    }

    pub fn set_ssl(&self, ssl: HttpSSLContext) {
        if let Ok(mut ssl_ctx) = self.ssl.lock() {
            *ssl_ctx = Some(ssl);
        }
    }
}

static RUNNING: AtomicBool = AtomicBool::new(true);

pub struct HttpServer {
    listener: TcpListener,
    http_version: Arc<HttpVersion>,
    locations: Arc<Vec<(String, Arc<HttpLocationContext>)>>,
    ssl: Option<Arc<ServerConfig>>,
}

impl HttpServer {
    pub fn new(ctx: &Arc<HttpServerContext>) -> Self {
        let listen = ctx.listen();
        println!("Listening on: {}", listen);

        let http_version = Arc::new(ctx.http_version.lock().unwrap().clone());
        let locations = Arc::new(ctx.get_locations());
        let ssl = {
            let ssl_guard = ctx.ssl.lock().unwrap();
            if ssl_guard.is_none() {
                None
            } else {
                let ssl_ctx = ssl_guard.as_ref().unwrap();
                let ssl = HttpSSL::new(ssl_ctx).unwrap();
                let pem_key = ssl.cert_key.pri_key.private_key_to_pem_pkcs8().unwrap();
                let pri_key =
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from_pem_slice(&pem_key).unwrap());

                let pem_cert = ssl.cert.cert.to_pem().unwrap();
                let cert = CertificateDer::from_pem_slice(&pem_cert).unwrap();

                let config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert], pri_key)
                    .unwrap();

                Some(Arc::new(config))
            }
        };

        println!("SSL enabled: {}", ssl.is_some());

        Self {
            listener: TcpListener::bind(listen).unwrap(),
            http_version,
            locations,
            ssl,
        }
    }

    pub fn start(self) -> thread::JoinHandle<()> {
        println!("Server started");
        thread::spawn(move || {
            self.listener.set_nonblocking(true).unwrap();

            if self.locations.is_empty() {
                eprintln!("No locations configured for server");
                return;
            }

            while RUNNING.load(Ordering::SeqCst) {
                match self.listener.incoming().next() {
                    Some(Ok(mut stream)) => {
                        let from = stream.peer_addr().unwrap().to_string();
                        println!("Traffic from: {from}");

                        let locations = self.locations.clone();
                        let http_version = self.http_version.clone();
                        let ssl_config = self.ssl.clone();

                        if let Ok(pool) = THREAD_POOL.lock() {
                            if let Err(e) = pool.spawn(move || {
                                if let Some(ssl_config) = ssl_config {
                                    let mut conn = match ServerConnection::new(ssl_config) {
                                        Ok(c) => c,
                                        Err(e) => {
                                            eprintln!("Failed to create TLS connection: {}", e);
                                            return;
                                        }
                                    };

                                    let mut tls_stream =
                                        rustls::Stream::new(&mut conn, &mut stream);

                                    match tls_stream.flush() {
                                        Ok(_) => {
                                            if let Err(e) = handle_connection(
                                                &mut tls_stream,
                                                &locations,
                                                &http_version,
                                            ) {
                                                eprintln!("Error handling TLS connection: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("TLS handshake error: {}", e);
                                        }
                                    }
                                } else if let Err(e) =
                                    handle_connection(&mut stream, &locations, &http_version)
                                {
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

fn handle_connection<S: Read + Write>(
    stream: &mut S,
    locations: &[(String, Arc<HttpLocationContext>)],
    http_version: &HttpVersion,
) -> std::io::Result<()> {
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer)?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..n]);
    let path = parse_request_path(&request);

    let response = locations
        .iter()
        .find(|(loc_path, _)| path == loc_path)
        .and_then(|(_, ctx)| HttpLocation::new((**ctx).clone()).handle(200))
        .unwrap_or_else(|| create_404_response(http_version));

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

fn create_404_response(http_version: &HttpVersion) -> HttpResponse {
    let mut response = HttpResponse::new();
    response.set_status_line(http_version.clone(), 404);
    response.set_header("Content-Type", "text/plain");
    response.set_body("404 Not Found");
    response
}
