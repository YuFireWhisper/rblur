use std::{
    any::TypeId,
    collections::HashMap,
    sync::{atomic::AtomicPtr, Arc, Mutex},
    thread,
};

use crate::{
    core::config::{
        command::Command, config_context::ConfigContext, config_file_parser::parse_context_of,
    },
    register_commands,
};

use super::http_server::{HttpServer, HttpServerContext};

register_commands!(Command::new("http", vec![], handle_create_http),);

pub fn handle_create_http(ctx: &mut ConfigContext) {
    let prev_ctx = ctx.current_ctx.take();
    let prev_block_type_id = ctx.current_block_type_id.take();

    let http_ctx = Box::new(HttpContext::new());
    let http_ctx_ptr = Box::into_raw(http_ctx);
    
    ctx.current_ctx = Some(AtomicPtr::new(http_ctx_ptr as *mut u8));
    ctx.current_block_type_id = Some(TypeId::of::<HttpContext>());

    parse_context_of(ctx).expect("Error at handle_create_http");

    ctx.spare2 = ctx.current_ctx.take();
    
    ctx.current_ctx = prev_ctx;
    ctx.current_block_type_id = prev_block_type_id;
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
        let addr_str = if addr.chars().all(|c| c.is_ascii_digit()) {
            format!("0.0.0.0:{}", addr)
        } else {
            addr.to_string()
        };
        
        if let Ok(mut servers) = self.servers.lock() {
            servers.insert(addr_str, ctx);
        }
    }

    pub fn get_servers(&self) -> Vec<Arc<HttpServerContext>> {
        self.servers.lock()
            .map(|servers| servers.values().cloned().collect())
            .unwrap_or_default()
    }
}

pub struct HttpManager {
    ctx: Arc<HttpContext>,
    server_handles: Vec<thread::JoinHandle<()>>,
}

impl HttpManager {
    pub fn new(ctx: Arc<HttpContext>) -> Self {
        Self {
            ctx,
            server_handles: Vec::new(),
        }
    }

    pub fn start(&mut self) {
        println!("Starting HTTP servers...");
        let servers = self.ctx.get_servers();
        
        for srv_ctx in servers {
            let server = HttpServer::new(&srv_ctx);
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
