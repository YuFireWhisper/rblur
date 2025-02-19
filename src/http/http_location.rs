use http::{StatusCode, Version};
use reqwest::blocking::Client;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Arc, Mutex,
    },
};

use crate::{
    core::config::{
        command::{CommandBuilder, ParameterBuilder},
        config_manager::get_config_param,
    },
    register_commands,
};

use super::{
    http_request::HttpRequest,
    http_response::{get_content_type, HttpResponse},
};

register_commands!(
    CommandBuilder::new("location")
        .is_block()
        .allowed_parents(vec!["server".to_string()])
        .display_name("en", "Location")
        .display_name("zh-tw", "位置")
        .desc(
            "en",
            "Creates a new configuration block for defining a specific URL path handling"
        )
        .desc("zh-tw", "建立處理特定 URL 路徑的配置區塊")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Path")
            .display_name("zh-tw", "路徑")
            .type_name("String")
            .is_required(true)
            .default("")
            .desc(
                "en",
                "Specifies the URL path pattern to be matched for this location block"
            )
            .desc("zh-tw", "定義此位置區塊要匹配的 URL 路徑模式")
            .build()])
        .build(handle_create_location),
    CommandBuilder::new("static_file")
        .allowed_parents(vec!["location".to_string()])
        .display_name("en", "Static File")
        .display_name("zh-tw", "靜態檔案")
        .desc(
            "en",
            "Configures serving a static file from the specified path"
        )
        .desc("zh-tw", "配置從指定路徑提供靜態檔案服務")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "File Path")
            .display_name("zh-tw", "檔案路徑")
            .type_name("String")
            .is_required(true)
            .default("")
            .desc(
                "en",
                "Full system path to the static file that will be served"
            )
            .desc("zh-tw", "將被提供服務的靜態檔案的完整系統路徑")
            .build()])
        .build(handle_set_static_file),
    CommandBuilder::new("port_forward")
        .allowed_parents(vec!["location".to_string()])
        .display_name("en", "Port Forward")
        .display_name("zh-tw", "端口轉發")
        .desc(
            "en",
            "Redirects incoming requests to a different server address"
        )
        .desc("zh-tw", "將收到的請求重新導向到另一個伺服器地址")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Forward Address")
            .display_name("zh-tw", "轉發地址")
            .type_name("String")
            .is_required(true)
            .default("")
            .desc(
                "en",
                "Target server address where requests will be forwarded"
            )
            .desc("zh-tw", "請求將被轉發的目標伺服器地址")
            .build()])
        .build(handle_port_forward)
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

pub fn handle_create_location(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    _config: &Value,
) {
    let location_ctx = Arc::new(HttpLocationContext::new());
    let raw_ptr = Arc::into_raw(location_ctx.clone()) as *mut u8;
    ctx.current_ctx = Some(AtomicPtr::new(raw_ptr));
    ctx.current_block_type_id = Some(std::any::TypeId::of::<HttpLocationContext>());
}

pub fn handle_set_static_file(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let file_path = get_config_param(config, 0).expect("Missing static_file parameter");
    if file_path.is_empty() {
        return;
    }
    if let Some(ctx_ptr) = &ctx.current_ctx {
        if let Some(location_ctx) = clone_arc_from_atomic_ptr::<HttpLocationContext>(ctx_ptr) {
            println!("Setting static file: {}", file_path);
            let content =
                Arc::new(std::fs::read_to_string(&file_path).expect("Failed to read static file"));
            let content_type = get_content_type(&file_path).to_string();
            let handler = Box::new(move |_req: &HttpRequest| {
                println!("Serving static file: {}", file_path);
                let mut resp = HttpResponse::new();
                resp.set_status_line(Version::HTTP_11, StatusCode::OK);
                resp.set_header("Content-Type", &content_type);
                resp.set_body(&content);
                resp
            });
            location_ctx.set_handler(200, handler);
        }
    }
}

pub fn handle_port_forward(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let forward_addr = get_config_param(config, 0).expect("Missing port_forward parameter");
    if forward_addr.is_empty() {
        return;
    }

    if let Some(ctx_ptr) = &ctx.current_ctx {
        if let Some(location_ctx) = clone_arc_from_atomic_ptr::<HttpLocationContext>(ctx_ptr) {
            let forward_addr = forward_addr.to_string();
            let handler = Box::new(move |req: &HttpRequest| {
                let client = Client::new();
                let url = format!("{}{}", forward_addr, req.path());
                let result = client.get(&url).send();
                match result {
                    Ok(response) => {
                        let status = StatusCode::from_u16(response.status().as_u16())
                            .expect("Invalid status code");
                        let body = response
                            .text()
                            .unwrap_or_else(|_| "Error reading forwarded response".into());
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(Version::HTTP_11, status);
                        resp.set_body(&body);
                        resp
                    }
                    Err(_) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(Version::HTTP_11, StatusCode::BAD_GATEWAY);
                        resp.set_body("Bad Gateway");
                        resp
                    }
                }
            });
            location_ctx.set_handler(200, handler);
        }
    }
}

pub type HttpHandlerFunction = Box<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static>;

#[derive(Default, Clone)]
pub struct HttpLocationContext {
    pub handlers: Arc<Mutex<HashMap<u16, HttpHandlerFunction>>>,
}

impl HttpLocationContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_handler(&self, code: u16, handler: HttpHandlerFunction) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.insert(code, handler);
        }
    }

    pub fn take_handlers(&self) -> HashMap<u16, HttpHandlerFunction> {
        let mut map = HashMap::new();
        if let Ok(mut handlers) = self.handlers.lock() {
            std::mem::swap(&mut *handlers, &mut map);
        }
        map
    }
}
