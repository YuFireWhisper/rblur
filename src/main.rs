use std::sync::{atomic::Ordering, Arc};
use std::thread;
use std::time::Duration;

use blur::{
    core::config::{
        config_context::ConfigContext, config_file_parser::parse_context_of,
        config_manager::ConfigManager,
    },
    http::http_manager::{HttpContext, HttpManager},
};

fn main() {
    ConfigManager::init();

    let mut ctx = ConfigContext::new("/home/yuwhisper/projects/blur/config/config_template")
        .expect("Failed to create config context");

    parse_context_of(&mut ctx).expect("Failed to parse context");
    println!("Configuration parsing complete");

    if let Some(http_ctx_ptr) = ctx.spare2.take() {
        let http_ptr = http_ctx_ptr.load(Ordering::SeqCst);
        let http_ctx = unsafe { Arc::new(*Box::from_raw(http_ptr as *mut HttpContext)) };

        if let Ok(servers_count) = http_ctx.servers.lock() {
            println!("\nNumber of servers: {}", servers_count.len());
        }

        let mut manager = HttpManager::new(http_ctx);
        manager.start();

        manager.join();

        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
}
