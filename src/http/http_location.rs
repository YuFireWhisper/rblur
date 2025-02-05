use crate::http::http_server::HttpServerContext;
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
    http_type::HttpVersion,
    http_request::HttpRequest,
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

/// 在 location 區塊開始時建立一個 HttpLocationContext，供子命令登錄 handler 使用
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
        // 修改 handler 的簽名，符合 Processor 的要求：接受 &HttpRequest 參數
        let handler = Box::new(move |_req: &HttpRequest| {
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

/// 此區塊僅用於配置階段保存各路由的處理器，待 Server 建立時轉登 Processor
/// 注意：此結構在運行時不再直接被使用，只在配置中暫存 handler 資訊
pub type HttpHandlerFunction = Box<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static>;

#[derive(Default, Clone)]
pub struct HttpLocationContext {
    // 鍵為狀態碼（例如200），值為處理器函數
    pub handlers: Arc<Mutex<HashMap<u32, HttpHandlerFunction>>>,
}

impl HttpLocationContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_handler(&self, code: u32, handler: HttpHandlerFunction) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.insert(code, handler);
        }
    }

    pub fn take_handlers(&self) -> HashMap<u32, HttpHandlerFunction> {
        let mut map = HashMap::new();
        if let Ok(mut handlers) = self.handlers.lock() {
            std::mem::swap(&mut *handlers, &mut map);
        }
        map
    }
}
