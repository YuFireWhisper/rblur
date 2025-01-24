use std::{
    any::TypeId,
    collections::HashMap,
    fs,
    sync::{atomic::Ordering, Arc},
};

use crate::{
    core::config::{
        command::Command, config_context::ConfigContext, config_file_parser::ConfigFileParser,
    },
    register_commands,
};

use super::{
    get_context_u8,
    http_response::{get_content_type, HttpResponse},
    http_server::HttpServerContext,
    http_type::HttpVersion,
};

register_commands!(
    Command::new(
        "location",
        vec![TypeId::of::<HttpServerContext>()],
        handle_create_location,
    ),
    Command::new(
        "static_file",
        vec![TypeId::of::<HttpLocationContext>()],
        handle_set_static_file
    )
);

pub fn handle_create_location(ctx: &mut ConfigContext) {
    let path = ctx.current_cmd_args[1].clone();
    let prev_ctx = ctx.current_ctx.take();
    let prev_block_type_id = ctx.current_block_type_id.take();

    ctx.current_ctx = Some(get_context_u8(&mut HttpLocationContext::new()));
    ctx.current_block_type_id = Some(TypeId::of::<HttpLocationContext>());

    {
        let mut parser = ConfigFileParser::instance().lock().unwrap();
        parser.parse(ctx).unwrap();
    }

    if let Some(srv_ctx_ptr) = &prev_ctx {
        let srv_ptr = srv_ctx_ptr.load(Ordering::SeqCst);
        let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };

        if let Some(loc_ctx_ptr) = &ctx.current_ctx.take() {
            let loc_ptr = loc_ctx_ptr.load(Ordering::SeqCst);
            srv_ctx.set_location(&path, loc_ptr);
        }
    }

    ctx.current_ctx = prev_ctx;
    ctx.current_block_type_id = prev_block_type_id;
}

pub fn handle_set_static_file(ctx: &mut ConfigContext) {
    let file_path = ctx.current_cmd_args[0].clone();
    if let Some(loc_ctx_ptr) = &ctx.current_ctx {
        let loc_ptr = loc_ctx_ptr.load(Ordering::SeqCst);
        let ctn = Arc::new(fs::read_to_string(&file_path).unwrap());
        let handler = Box::new(move || {
            let mut resp = HttpResponse::new();
            resp.set_status_line(HttpVersion::Http1_1, 200);
            resp.set_header("Content-Type", get_content_type(&file_path));
            resp.set_body(&ctn);
            resp
        });

        let loc_ctx = unsafe { &mut *(loc_ptr as *mut HttpLocationContext) };

        if let Some(handlers) = Arc::get_mut(&mut loc_ctx.handlers) {
            handlers.insert(200, handler);
        }
    }
}

#[derive(Default, Clone)]
pub struct HttpLocationContext {
    pub path: String,
    handlers: Arc<HashMap<u32, Box<dyn Fn() -> HttpResponse + Send + Sync + 'static>>>,
}

impl HttpLocationContext {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone)]
pub struct HttpLocation {
    pub ctx: HttpLocationContext,
}

impl HttpLocation {
    pub fn new(ctx: HttpLocationContext) -> Self {
        Self { ctx }
    }

    pub fn handle(&self, code: u32) -> Option<HttpResponse> {
        if let Some(handler) = self.ctx.handlers.get(&code) {
            return Some(handler());
        }

        None
    }
}
