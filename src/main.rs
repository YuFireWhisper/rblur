use std::time::Duration;
use std::{rc::Rc, sync::atomic::Ordering, thread};

use blur::{
    core::config::{
        config_context::ConfigContext, config_file_parser::parse_context_of,
        config_manager::ConfigManager,
    },
    http::http_manager::{HttpContext, HttpManager},
};

fn main() {
    ConfigManager::init();

    let mut ctx =
        ConfigContext::new("/home/yuwhisper/projects/blur/config/config_template").unwrap();

    parse_context_of(&mut ctx).unwrap();
    println!("解析完畢");

    if let Some(http_ctx_ptr) = ctx.spare2.take() {
        let http_ptr = http_ctx_ptr.load(Ordering::SeqCst);
        let http_ctx = unsafe { Rc::new(*Box::from_raw(http_ptr as *mut HttpContext)) };

        println!();
        println!("Number of servers: {}", http_ctx.servers.len());

        let mut manager = HttpManager::new(&http_ctx);
        manager.start();

        while let Some(handle) = manager.server_handles.pop() {
            handle.join().unwrap();
        }

        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
}
