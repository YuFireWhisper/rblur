use http::{Method, StatusCode, Version};
use rustls::pki_types::pem::PemObject;
use serde_json::Value;
use std::{
    env,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
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
    core::{
        config::{
            command::{CommandBuilder, ParameterBuilder},
            config_context::ConfigContext,
            config_manager::{bool_str_to_bool, get_config_param},
        },
        processor::{HttpProcessor, Processor},
    },
    events::thread_pool::THREAD_POOL,
    http::{http_ssl::HttpSSL, web_config},
    register_commands,
};

use super::{http_location::HttpLocationContext, web_config::WebConfig};

register_commands!(
    CommandBuilder::new("server")
        .is_block()
        .allowed_parents(vec!["http".to_string()])
        .display_name("en", "Server")
        .display_name("zh-tw", "伺服器")
        .desc(
            "en",
            "Creates a new server configuration block within the HTTP context"
        )
        .desc("zh-tw", "在 HTTP 上下文中建立新的伺服器配置區塊")
        .build(handle_create_server),
    CommandBuilder::new("listen")
        .allowed_parents(vec!["server".to_string()])
        .display_name("en", "Listen Address")
        .display_name("zh-tw", "監聽位址")
        .desc(
            "en",
            "Configures the network interface and port for server connections"
        )
        .desc("zh-tw", "配置伺服器連線的網路介面和埠號")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Address")
            .display_name("zh-tw", "監聽位址")
            .type_name("String")
            .is_required(true)
            .default("")
            .desc(
                "en",
                "Network interface IP address and port number for server to accept connections"
            )
            .desc("zh-tw", "伺服器接受連線的網路介面 IP 位址和埠號")
            .build()])
        .build(handle_set_listen),
    CommandBuilder::new("server_name")
        .allowed_parents(vec!["server".to_string()])
        .display_name("en", "Server Name")
        .display_name("zh-tw", "伺服器名稱")
        .desc("en", "Assigns a name to identify the server configuration")
        .desc("zh-tw", "為伺服器配置指定識別名稱")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Name")
            .display_name("zh-tw", "伺服器名稱")
            .type_name("String")
            .is_required(true)
            .default("")
            .desc("en", "Unique identifier for the server configuration")
            .desc("zh-tw", "伺服器配置的唯一識別名稱")
            .build()])
        .build(handle_set_server_name),
    CommandBuilder::new("web_config")
        .allowed_parents(vec!["server".to_string()])
        .display_name("en", "Web Config")
        .display_name("zh-tw", "網頁配置功能")
        .desc(
            "en",
            "Enables or disables web-based configuration for the server"
        )
        .desc("zh-tw", "啟用或停用伺服器的網頁配置功能")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Enable")
            .display_name("zh-tw", "網頁配置")
            .type_name("bool")
            .is_required(true)
            .default("true")
            .desc("en", "Toggles web configuration interface on or off")
            .desc("zh-tw", "開啟或關閉網頁配置介面")
            .build()])
        .build(handle_web_config)
);

fn clone_arc_from_atomic_ptr<T>(atomic_ptr: &AtomicPtr<u8>) -> Option<Arc<T>> {
    let raw = atomic_ptr.load(Ordering::SeqCst) as *const T;
    if raw.is_null() {
        None
    } else {
        unsafe {
            Arc::increment_strong_count(raw);
            Some(Arc::from_raw(raw))
        }
    }
}

pub fn handle_create_server(ctx: &mut ConfigContext, _config: &Value) {
    let server_ctx = Arc::new(HttpServerContext::new());
    let raw_ptr = Arc::into_raw(server_ctx.clone()) as *mut u8;
    ctx.current_ctx = Some(AtomicPtr::new(raw_ptr));
    ctx.current_block_type_id = Some(std::any::TypeId::of::<HttpServerContext>());
}

pub fn handle_set_listen(ctx: &mut ConfigContext, config: &Value) {
    let listen = get_config_param(config, 0).expect("Missing listen parameter");
    if let Some(ctx_ptr) = &ctx.current_ctx {
        if let Some(server_ctx) = clone_arc_from_atomic_ptr::<HttpServerContext>(ctx_ptr) {
            server_ctx.set_listen(&listen);
        }
    }
}

pub fn handle_set_server_name(ctx: &mut ConfigContext, config: &Value) {
    let server_name = get_config_param(config, 0).expect("Missing server_name parameter");
    if let Some(ctx_ptr) = &ctx.current_ctx {
        if let Some(server_ctx) = clone_arc_from_atomic_ptr::<HttpServerContext>(ctx_ptr) {
            server_ctx.add_server_name(&server_name);
        }
    }
}

pub fn handle_web_config(ctx: &mut ConfigContext, config: &Value) {
    let flag = get_config_param(config, 0).expect("Missing web_config parameter");
    if !bool_str_to_bool(&flag).expect("Invalid web_config value") {
        return;
    }
    if let Some(ctx_ptr) = &ctx.current_ctx {
        if let Some(server_ctx) = clone_arc_from_atomic_ptr::<HttpServerContext>(ctx_ptr) {
            let storage_path = get_default_storage_path();
            let web_config = WebConfig::new(&storage_path).expect("Failed to create web config");
            if let Ok(mut web_config_lock) = server_ctx.web_config.lock() {
                *web_config_lock = Some(Arc::new(web_config));
            }
        }
    }
}

#[derive(Default)]
pub struct HttpServerContext {
    listen: Mutex<String>,
    server_names: Mutex<Vec<String>>,
    http_version: Mutex<Version>,
    processor: Mutex<HttpProcessor>,
    pub web_config: Mutex<Option<Arc<WebConfig>>>,
}

impl HttpServerContext {
    pub fn new() -> Self {
        Self {
            listen: Mutex::new("127.0.0.1:8080".to_string()),
            server_names: Mutex::new(Vec::new()),
            http_version: Mutex::new(Version::default()),
            processor: Mutex::new(HttpProcessor::new()),
            web_config: Mutex::new(None),
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

    pub fn get_http_version(&self) -> Version {
        *self.http_version.lock().unwrap()
    }
}

pub struct HttpServer {
    listener: TcpListener,
    http_version: Arc<Version>,
    processor: Arc<HttpProcessor>,
    ssl: Option<Arc<ServerConfig>>,
    running: Arc<AtomicBool>,
}

impl HttpServer {
    pub fn new(server_config: &ConfigContext) -> Self {
        let server_ctx_arc: Arc<HttpServerContext> = if let Some(ptr) = &server_config.current_ctx {
            let raw = ptr.load(Ordering::SeqCst);
            unsafe {
                Arc::increment_strong_count(raw as *const HttpServerContext);
                Arc::from_raw(raw as *const HttpServerContext)
            }
        } else {
            panic!("Server block missing HttpServerContext");
        };

        let server_ctx = server_ctx_arc.clone();
        std::mem::forget(server_ctx_arc);

        let listen = server_ctx.listen();
        println!("Listening on: {}", listen);

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
                        if let Some(loc_ctx) = clone_arc_from_atomic_ptr::<HttpLocationContext>(ptr)
                        {
                            let handlers = loc_ctx.take_handlers();
                            for (code, handler) in handlers {
                                if let Ok(mut proc_lock) = server_ctx.processor.lock() {
                                    proc_lock.add_handler(
                                        path.clone(),
                                        StatusCode::from_u16(code).unwrap(),
                                        &Method::OPTIONS,
                                        handler,
                                    );
                                }
                            }
                        }
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

        if let Some(web_config) = server_ctx.web_config.lock().unwrap().as_ref() {
            let web_config = Arc::clone(web_config);
            if let Ok(proc_lock) = server_ctx.processor.lock() {
                web_config::add_all_web_config_handlers(web_config, proc_lock);
            }
        }

        let processor = {
            let mut proc_lock = server_ctx.processor.lock().unwrap();
            std::mem::replace(&mut *proc_lock, HttpProcessor::new())
        };

        let listener = TcpListener::bind(&listen).unwrap();
        let http_version = Arc::new(server_ctx.get_http_version());

        Self {
            listener,
            http_version,
            processor: Arc::new(processor),
            ssl: ssl_config,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn start(self) -> thread::JoinHandle<()> {
        println!("Server started");
        let running_flag = self.running.clone();
        let listener = self.listener;
        let http_version = self.http_version.clone();
        let processor = self.processor.clone();
        let ssl_config = self.ssl.clone();

        thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("Failed to set non-blocking");

            if processor.is_empty() {
                eprintln!("No routes configured for server");
                return;
            }

            while running_flag.load(Ordering::SeqCst) {
                match listener.incoming().next() {
                    Some(Ok(stream)) => {
                        println!("Connection from: {}", stream.peer_addr().unwrap());
                        process_connection(
                            stream,
                            processor.clone(),
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
    processor: Arc<HttpProcessor>,
    http_version: Arc<Version>,
    ssl_config: Option<Arc<ServerConfig>>,
) {
    if let Ok(pool) = THREAD_POOL.lock() {
        let _ = pool.spawn(move || {
            let result = if let Some(ssl_cfg) = ssl_config {
                process_tls_connection(stream, ssl_cfg, &processor, &http_version)
            } else {
                process_plain_connection(stream, &processor, &http_version)
            };
            if let Err(e) = result {
                eprintln!("Error handling connection: {}", e);
            }
        });
    } else {
        eprintln!("Thread pool error");
    }
}

fn process_plain_connection(
    mut stream: TcpStream,
    processor: &HttpProcessor,
    http_version: &Version,
) -> std::io::Result<()> {
    handle_connection(&mut stream, processor, http_version)
}

fn process_tls_connection(
    mut stream: TcpStream,
    ssl_cfg: Arc<ServerConfig>,
    processor: &HttpProcessor,
    http_version: &Version,
) -> std::io::Result<()> {
    let mut conn = ServerConnection::new(ssl_cfg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);

    tls_stream.flush()?;
    handle_connection(&mut tls_stream, processor, http_version)
}

fn handle_connection<S: Read + Write>(
    stream: &mut S,
    processor: &HttpProcessor,
    http_version: &Version,
) -> std::io::Result<()> {
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer)?;
    if n == 0 {
        return Ok(());
    }
    let request_bytes = buffer[..n].to_vec();

    let response_bytes = match processor.process(request_bytes) {
        Ok(resp) => resp,
        Err(_) => HttpProcessor::create_404_response(http_version).as_bytes(),
    };

    stream.write_all(&response_bytes)?;
    stream.flush()?;
    Ok(())
}

pub fn get_default_storage_path() -> PathBuf {
    let app_name = env!("CARGO_PKG_NAME");

    #[cfg(target_os = "linux")]
    {
        let base_dir = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib"));

        base_dir.join(".local/share").join(app_name)
    }
}
