use std::{rc::Rc, sync::atomic::Ordering};

use blur::{
    core::config::{
        config_context::ConfigContext, config_file_parser::ConfigFileParser,
        config_manager::ConfigManager,
    },
    http::http_manager::{HttpContext, HttpManager},
};

fn main() {
    ConfigManager::init();
    ConfigFileParser::init("/home/yuwhisper/projects/blur/config/config_template").unwrap();

    let mut ctx = ConfigContext::new();
    ConfigFileParser::instance()
        .lock()
        .unwrap()
        .parse(&mut ctx)
        .unwrap();

    if let Some(http_ctx_ptr) = ctx.spare2.take() {
        let http_ptr = http_ctx_ptr.load(Ordering::SeqCst);
        let http_ctx = unsafe { Rc::new(*Box::from_raw(http_ptr as *mut HttpContext)) };

        let mut manager = HttpManager::new(&http_ctx);
        manager.start();

        while let Some(handle) = manager.server_handles.pop() {
            handle.join().unwrap();
        }
    } 
}
