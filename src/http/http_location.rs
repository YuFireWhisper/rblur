use std::{
    any::TypeId,
    collections::HashMap,
    sync::{atomic::{AtomicPtr, Ordering}, Arc, Mutex},
};

use crate::{
    core::config::{
        command::Command, config_context::ConfigContext,
    },
    register_commands,
};

use super::{
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
    let location_ctx = Arc::new(HttpLocationContext::new());
    let location_raw = Arc::into_raw(location_ctx.clone()) as *mut u8;
    ctx.current_ctx = Some(AtomicPtr::new(location_raw));
    ctx.current_block_type_id = Some(TypeId::of::<HttpLocationContext>());
}

pub fn handle_set_static_file(ctx: &mut ConfigContext) {
    let file_path = ctx.current_cmd_args[0].clone();
    println!("Static file path: {}", file_path);
    if let Some(loc_ctx_ptr) = &ctx.current_ctx {
        let loc_ptr = loc_ctx_ptr.load(Ordering::SeqCst);
        let content = Arc::new(std::fs::read_to_string(&file_path).unwrap());
        let content_type = get_content_type(&file_path).to_string();
        let handler = Box::new(move || {
            let mut resp = HttpResponse::new();
            resp.set_status_line(HttpVersion::Http1_1, 200);
            resp.set_header("Content-Type", &content_type);
            resp.set_body(&content);
            resp
        });
        let loc_ctx = unsafe { &mut *(loc_ptr as *mut HttpLocationContext) };
        loc_ctx.set_handler(200, handler);
    }
}


type HandlerFunction = Box<dyn Fn() -> HttpResponse + Send + Sync + 'static>;
type HandlersMap = HashMap<u32, HandlerFunction>;

#[derive(Default, Clone)]
pub struct HttpLocationContext {
    handlers: Arc<Mutex<HandlersMap>>,
}

impl HttpLocationContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_handler(&self, code: u32, handler: HandlerFunction) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.insert(code, handler);
        }
    }

    pub fn get_handler(&self, code: u32) -> Option<HttpResponse> {
        self.handlers
            .lock()
            .ok()
            .and_then(|handlers| handlers.get(&code).map(|handler| handler()))
    }
}

#[derive(Clone)]
pub struct HttpLocation {
    ctx: HttpLocationContext,
}

impl HttpLocation {
    pub fn new(ctx: HttpLocationContext) -> Self {
        Self { ctx }
    }

    pub fn handle(&self, code: u32) -> Option<HttpResponse> {
        self.ctx.get_handler(code)
    }
}
