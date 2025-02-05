use rustls::pki_types::pem::PemObject;
use std::{
    any::TypeId,
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
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
    core::config::{command::Command, config_context::ConfigContext},
    events::thread_pool::THREAD_POOL,
    http::http_ssl::HttpSSL,
    register_commands,
};

use super::{
    http_location::{HttpLocation, HttpLocationContext},
    http_manager::HttpContext,
    http_response::HttpResponse,
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
    println!("Creating server");
    let server_ctx = Arc::new(HttpServerContext::new());
    let server_raw = Arc::into_raw(server_ctx.clone()) as *mut u8;
    ctx.current_ctx = Some(atomic_ptr_new(server_raw));
    ctx.current_block_type_id = Some(TypeId::of::<HttpServerContext>());
}

pub fn handle_set_listen(ctx: &mut ConfigContext) {
    let listen = ctx.current_cmd_args.first().unwrap();
    if let Some(srv_ctx_ptr) = &ctx.current_ctx {
        let srv_ptr = srv_ctx_ptr.load(Ordering::SeqCst);
        if !srv_ptr.is_null() {
            let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };
            srv_ctx.set_listen(listen);
        }
    }
}

pub fn handle_set_server_name(ctx: &mut ConfigContext) {
    let server_name = ctx.current_cmd_args.first().unwrap();
    if let Some(srv_ctx_ptr) = &ctx.current_ctx {
        let srv_ptr = srv_ctx_ptr.load(Ordering::SeqCst);
        if !srv_ptr.is_null() {
            let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };
            srv_ctx.add_server_name(server_name);
        }
    }
}

fn atomic_ptr_new<T>(ptr: *mut T) -> std::sync::atomic::AtomicPtr<u8> {
    std::sync::atomic::AtomicPtr::new(ptr as *mut u8)
}

#[derive(Default)]
pub struct HttpServerContext {
    listen: Mutex<String>,
    server_names: Mutex<Vec<String>>,
    http_version: Mutex<HttpVersion>,
    locations: Mutex<HashMap<String, Arc<HttpLocationContext>>>,
}

impl HttpServerContext {
    pub fn new() -> Self {
        Self {
            listen: Mutex::new("127.0.0.1:8080".to_string()),
            server_names: Mutex::new(Vec::new()),
            locations: Mutex::new(HashMap::new()),
            http_version: Mutex::new(HttpVersion::default()),
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

    pub fn get_http_version(&self) -> HttpVersion {
        self.http_version.lock().unwrap().clone()
    }
}

pub struct HttpServer {
    listener: TcpListener,
    http_version: Arc<HttpVersion>,
    locations: Arc<Vec<(String, Arc<HttpLocationContext>)>>,
    ssl: Option<Arc<ServerConfig>>,
    running: Arc<AtomicBool>,
}

impl HttpServer {
    pub fn new(server_config: &ConfigContext) -> Self {
        let server_arc: Arc<HttpServerContext> = if let Some(ptr) = &server_config.current_ctx {
            let srv_raw = ptr.load(Ordering::SeqCst);
            unsafe { Arc::from_raw(srv_raw as *const HttpServerContext) }
        } else {
            panic!("Server block missing HttpServerContext");
        };
        let server_ctx = server_arc.clone();
        std::mem::forget(server_arc);

        let listen = server_ctx.listen();
        println!("Listening on: {}", listen);

        let mut locations_map: HashMap<String, Arc<HttpLocationContext>> = HashMap::new();
        let mut ssl_config: Option<Arc<ServerConfig>> = None;

        for child in &server_config.children {
            match child.block_name.trim() {
                "location" => {
                    let path = child
                        .block_args
                        .first()
                        .expect("location block must have a path")
                        .clone();
                    if let Some(ptr) = &child.current_ctx {
                        let loc_raw = ptr.load(Ordering::SeqCst);
                        let loc_arc: Arc<HttpLocationContext> =
                            unsafe { Arc::from_raw(loc_raw as *const HttpLocationContext) };
                        locations_map.insert(path, loc_arc.clone());
                        std::mem::forget(loc_arc);
                    }
                }
                "ssl" => {
                    if child.current_ctx.is_some() {
                        if let Ok(http_ssl) = HttpSSL::from_config(child) {
                            let pem_key = http_ssl
                                .cert_key
                                .pri_key
                                .private_key_to_pem_pkcs8()
                                .unwrap();
                            let pri_key = PrivateKeyDer::Pkcs8(
                                PrivatePkcs8KeyDer::from_pem_slice(&pem_key).expect("Invalid key"),
                            );
                            let pem_cert = http_ssl.cert.cert.to_pem().unwrap();
                            let cert = CertificateDer::from_pem_slice(&pem_cert).unwrap();

                            ssl_config = Some(Arc::new(
                                ServerConfig::builder()
                                    .with_no_client_auth()
                                    .with_single_cert(vec![cert], pri_key)
                                    .unwrap(),
                            ));
                        } else {
                            eprintln!("Failed to create SSL config");
                        }
                    }
                }
                _ => {}
            }
        }

        let locations: Vec<(String, Arc<HttpLocationContext>)> =
            locations_map.into_iter().collect();
        let listener = TcpListener::bind(&listen).unwrap();
        let http_version = Arc::new(server_ctx.get_http_version());

        println!("SSL enabled: {}", ssl_config.is_some());

        Self {
            listener,
            http_version,
            locations: Arc::new(locations),
            ssl: ssl_config,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn start(self) -> thread::JoinHandle<()> {
        println!("Server started");
        let running_flag = self.running.clone();
        let listener = self.listener;
        let locations = self.locations.clone();
        let http_version = self.http_version.clone();
        let ssl_config = self.ssl.clone();

        thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("Failed to set non-blocking");

            if locations.is_empty() {
                eprintln!("No locations configured for server");
                return;
            }

            while running_flag.load(Ordering::SeqCst) {
                match listener.incoming().next() {
                    Some(Ok(stream)) => {
                        println!("Connection from: {}", stream.peer_addr().unwrap());
                        process_connection(
                            stream,
                            locations.clone(),
                            http_version.clone(),
                            ssl_config.clone(),
                        );
                    }
                    Some(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Some(Err(e)) => {
                        eprintln!("Connection failed: {}", e);
                    }
                    None => break,
                }
            }
            println!("Server stopped accepting connections.");
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        println!("Server stop requested");
    }
}

fn process_connection(
    stream: TcpStream,
    locations: Arc<Vec<(String, Arc<HttpLocationContext>)>>,
    http_version: Arc<HttpVersion>,
    ssl_config: Option<Arc<ServerConfig>>,
) {
    if let Ok(pool) = THREAD_POOL.lock() {
        let _ = pool.spawn(move || {
            if let Err(e) = if let Some(ssl_cfg) = ssl_config {
                process_tls_connection(stream, ssl_cfg, locations, http_version)
            } else {
                process_plain_connection(stream, locations, http_version)
            } {
                eprintln!("Error handling connection: {}", e);
            }
        });
    } else {
        eprintln!("Thread pool error");
    }
}

fn process_plain_connection(
    mut stream: TcpStream,
    locations: Arc<Vec<(String, Arc<HttpLocationContext>)>>,
    http_version: Arc<HttpVersion>,
) -> std::io::Result<()> {
    handle_connection(&mut stream, &locations, &http_version)
}

fn process_tls_connection(
    mut stream: TcpStream,
    ssl_cfg: Arc<ServerConfig>,
    locations: Arc<Vec<(String, Arc<HttpLocationContext>)>>,
    http_version: Arc<HttpVersion>,
) -> std::io::Result<()> {
    let mut conn = ServerConnection::new(ssl_cfg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);

    tls_stream.flush()?;
    handle_connection(&mut tls_stream, &locations, &http_version)
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
