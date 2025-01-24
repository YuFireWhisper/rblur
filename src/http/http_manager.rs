use std::{any::TypeId, collections::HashMap, rc::Rc, sync::Arc, thread};

use crate::{core::config::{command::Command, config_context::ConfigContext, config_file_parser::ConfigFileParser}, register_commands};

use super::{
    get_context_u8,
    http_server::{HttpServer, HttpServerContext},
};

register_commands!(Command::new("http", vec![], handle_create_http),);

pub fn handle_create_http(ctx: &mut ConfigContext) {
    println!("g");
    let prev_ctx = ctx.current_ctx.take();
    let prev_block_type_id = ctx.current_block_type_id.take();

    ctx.current_ctx = Some(get_context_u8(&mut HttpContext::new()));
    ctx.current_block_type_id = Some(TypeId::of::<HttpContext>());

    {
        let mut parse = ConfigFileParser::instance().lock().unwrap();
        parse.parse(ctx).unwrap();
    }

    ctx.spare2 = ctx.current_ctx.take(); // For Main
    ctx.current_ctx = prev_ctx;
    ctx.current_block_type_id = prev_block_type_id;
}

#[derive(Default)]
pub struct HttpContext {
    servers: HashMap<String, Arc<HttpServerContext>>,
}

impl HttpContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_server(&mut self, addr: &str, ctx: Arc<HttpServerContext>) {
        let addr_str = if addr.chars().all(|c| c.is_ascii_digit()) {
            format!("0.0.0.0:{}", addr)
        } else {
            addr.to_string()
        };
        self.servers.insert(addr_str, ctx);
    }
}

pub struct HttpManager {
    pub ctx: Rc<HttpContext>,
    pub server_handles: Vec<thread::JoinHandle<()>>,
}

impl HttpManager {
    pub fn new(ctx: &Rc<HttpContext>) -> Self {
        Self {
            ctx: ctx.clone(),
            server_handles: Vec::new(),
        }
    }

    pub fn start(&mut self) {
        println!("Starting HTTP servers...");
        for srv_ctx in self.ctx.servers.values() {
            let server = HttpServer::new(srv_ctx);
            let handle = server.start();
            self.server_handles.push(handle);
        }
    }
}
