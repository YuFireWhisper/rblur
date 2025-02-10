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
            config_manager::{bool_str_to_bool, get_config_parame},
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
        .desc("en", "Configures a server block.")
        .desc("zh-tw", "配置伺服器塊")
        .build(handle_create_server),
    CommandBuilder::new("listen")
        .allowed_parents(vec!["server".to_string()])
        .display_name("en", "Listen")
        .display_name("zh-tw", "監聽")
        .desc("en", "Specifies the server's listening address.")
        .desc("zh-tw", "指定伺服器監聽的位址")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Address")
            .display_name("zh-tw", "位址")
            .type_name("String")
            .is_required(true)
            .default("")
            .desc("en", "The IP address and port to listen on.")
            .desc("zh-tw", "監聽的 IP 位址和埠號")
            .build()])
        .build(handle_set_listen),
    CommandBuilder::new("server_name")
        .allowed_parents(vec!["server".to_string()])
        .display_name("en", "Server Name")
        .display_name("zh-tw", "伺服器名稱")
        .desc("en", "Adds a server name.")
        .desc("zh-tw", "登錄伺服器名稱")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Name")
            .display_name("zh-tw", "名稱")
            .type_name("String")
            .is_required(true)
            .default("")
            .desc("en", "The server name to register.")
            .desc("zh-tw", "要登錄的伺服器名稱")
            .build()])
        .build(handle_set_server_name),
    CommandBuilder::new("web_config")
        .allowed_parents(vec!["server".to_string()])
        .display_name("en", "Web Config")
        .display_name("zh-tw", "網頁配置")
        .desc("en", "Enables web configuration for the server.")
        .desc("zh-tw", "啟用伺服器的網頁配置")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Enable")
            .display_name("zh-tw", "啟用")
            .type_name("bool")
            .is_required(true)
            .default("true")
            .desc("en", "Set to true to enable web configuration.")
            .desc("zh-tw", "設置為 true 以啟用網頁配置")
            .build()])
        .build(handle_web_config)
);

pub fn handle_create_server(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    _config: &Value,
) {
    println!("Creating server block");
    let server_ctx = Arc::new(HttpServerContext::new());
    let server_raw = Arc::into_raw(server_ctx.clone()) as *mut u8;
    ctx.current_ctx = Some(AtomicPtr::new(server_raw));
    ctx.current_block_type_id = Some(std::any::TypeId::of::<HttpServerContext>());
}

/// **handle_set_listen**
/// 設定伺服器監聽位址，需提供一個參數：監聽位址 (String)
pub fn handle_set_listen(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let listen = get_config_parame(config, 0).expect("Missing listen parameter");
    if let Some(srv_ctx_ptr) = &ctx.current_ctx {
        let srv_ptr = srv_ctx_ptr.load(std::sync::atomic::Ordering::SeqCst);
        if !srv_ptr.is_null() {
            let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };
            srv_ctx.set_listen(&listen);
        }
    }
}

/// **handle_set_server_name**
/// 登錄伺服器名稱，需提供一個參數：名稱 (String)
pub fn handle_set_server_name(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let server_name = get_config_parame(config, 0).expect("Missing server_name parameter");
    if let Some(srv_ctx_ptr) = &ctx.current_ctx {
        let srv_ptr = srv_ctx_ptr.load(std::sync::atomic::Ordering::SeqCst);
        if !srv_ptr.is_null() {
            let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };
            srv_ctx.add_server_name(&server_name);
        }
    }
}

/// **handle_web_config**
/// 設定伺服器的 web_config，需提供一個參數：啟用標記 (bool，以 "true" 或 "false" 表示)
pub fn handle_web_config(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let flag = get_config_parame(config, 0).expect("Missing web_config parameter");
    if !bool_str_to_bool(&flag).expect("Invalid web_config value") {
        return;
    }
    if let Some(srv_ctx_ptr) = &ctx.current_ctx {
        let srv_ptr = srv_ctx_ptr.load(std::sync::atomic::Ordering::SeqCst);
        if !srv_ptr.is_null() {
            let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };
            let storage_path = get_default_storage_path();
            let web_config = WebConfig::new(&storage_path).expect("Failed to create web config");
            if let Ok(mut web_config_lock) = srv_ctx.web_config.lock() {
                *web_config_lock = Some(Arc::new(web_config));
            }
        }
    }
}

/// HttpServerContext 保存伺服器配置，包括監聽位址、伺服器名稱與 processor
#[derive(Default)]
pub struct HttpServerContext {
    listen: Mutex<String>,
    server_names: Mutex<Vec<String>>,
    http_version: Mutex<Version>,
    processor: Mutex<HttpProcessor>,
    web_config: Mutex<Option<Arc<WebConfig>>>,
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

/// 代表最終運行的 HTTP 伺服器，持有 Processor 處理請求
pub struct HttpServer {
    listener: TcpListener,
    http_version: Arc<Version>,
    processor: Arc<HttpProcessor>,
    ssl: Option<Arc<ServerConfig>>,
    running: Arc<AtomicBool>,
}

impl HttpServer {
    /// 根據配置建立 HttpServer，主要步驟：
    /// 1. 從 ConfigContext 中取得 HttpServerContext
    /// 2. 遍歷所有子區塊（例如 location），從中提取各路由的處理器，登錄到 processor 中
    /// 3. 將 processor 從 HttpServerContext 中取出，並建立 Server
    pub fn new(server_config: &ConfigContext) -> Self {
        // 取得 server 區塊的 HttpServerContext
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

        let mut ssl_config: Option<Arc<ServerConfig>> = None;

        // 處理所有子區塊
        for child in &server_config.children {
            match child.block_name.trim() {
                "location" => {
                    // location 區塊第一個參數即為路徑
                    let path = child
                        .block_args
                        .first()
                        .expect("location block must have a path")
                        .clone();
                    if let Some(ptr) = &child.current_ctx {
                        let loc_raw = ptr.load(Ordering::SeqCst);
                        let loc_arc: Arc<HttpLocationContext> =
                            unsafe { Arc::from_raw(loc_raw as *const HttpLocationContext) };
                        let handlers = loc_arc.take_handlers();
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

        println!("SSL enabled: {}", ssl_config.is_some());

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
    println!("Processing connection");
    if let Ok(pool) = THREAD_POOL.lock() {
        println!("Processing connection in thread pool");
        let _ = pool.spawn(move || {
            println!("Handling connection");
            if let Err(e) = if let Some(ssl_cfg) = ssl_config {
                process_tls_connection(stream, ssl_cfg, &processor, &http_version)
            } else {
                process_plain_connection(stream, &processor, &http_version)
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
    println!("Processing TLS connection");
    let mut conn = ServerConnection::new(ssl_cfg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);

    tls_stream.flush()?;
    handle_connection(&mut tls_stream, processor, http_version)
}

/// 處理單一連線：讀取請求，透過 processor 產生回應
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

    // 呼叫 processor 處理請求
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
