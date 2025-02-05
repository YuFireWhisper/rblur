use std::{
    any::TypeId,
    collections::HashMap,
    sync::{atomic::AtomicPtr, Arc, Mutex},
    thread,
};

use crate::{
    core::config::{command::Command, config_context::ConfigContext},
    register_commands,
};

use super::http_server::{HttpServer, HttpServerContext};

register_commands!(Command::new("http", vec![], handle_create_http),);

pub fn handle_create_http(ctx: &mut ConfigContext) {
    let http_ctx = Arc::new(HttpContext::new());
    let http_raw = Arc::into_raw(http_ctx.clone()) as *mut u8;
    ctx.current_ctx = Some(AtomicPtr::new(http_raw));
    ctx.current_block_type_id = Some(TypeId::of::<HttpContext>());
}

#[derive(Default)]
pub struct HttpContext {
    pub servers: Mutex<HashMap<String, Arc<HttpServerContext>>>,
}

impl HttpContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_server(&self, addr: &str, ctx: Arc<HttpServerContext>) {
        println!("Setting server: {}", addr);
        let addr_str = if addr.chars().all(|c| c.is_ascii_digit()) {
            format!("0.0.0.0:{}", addr)
        } else {
            addr.to_string()
        };

        if let Ok(mut servers) = self.servers.lock() {
            servers.insert(addr_str, ctx);
        }
    }
}

pub struct HttpManager {
    servers: Vec<HttpServer>,
    server_handles: Vec<thread::JoinHandle<()>>,
}

impl HttpManager {
    pub fn new(http_config: &ConfigContext) -> Self {
        let mut servers = Vec::new();
        for server_ctx in &http_config.children {
            if server_ctx.block_name == "server" {
                if let Some(ptr) = server_ctx.current_ctx.as_ref() {
                    let srv_raw = ptr.load(std::sync::atomic::Ordering::SeqCst);
                    let srv_arc: Arc<HttpServerContext> =
                        unsafe { Arc::from_raw(srv_raw as *const HttpServerContext) };
                    let server = HttpServer::new(server_ctx);
                    servers.push(server);
                    std::mem::forget(srv_arc);
                }
            }
        }
        Self {
            servers,
            server_handles: Vec::new(),
        }
    }

    pub fn start(&mut self) {
        println!("Starting HTTP servers...");
        for server in self.servers.drain(..) {
            let handle = server.start();
            self.server_handles.push(handle);
        }
    }

    pub fn join(self) {
        for handle in self.server_handles {
            if let Err(e) = handle.join() {
                eprintln!("Error joining server thread: {:?}", e);
            }
        }
    }
}
