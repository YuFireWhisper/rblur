use std::thread;
use std::time::Duration;

use blur::http::http_server::get_default_storage_path;
use blur::{
    core::config::{config_loader, config_manager::ConfigManager},
    http::http_manager::HttpManager,
};

fn main() {
    ConfigManager::init();

    let config_path = Some("/home/yuwhisper/projects/blur/config/config_template");
    let storage_path = get_default_storage_path();

    println!("Storage path: {:?}", storage_path);

    let root_ctx = config_loader::load_config(
        storage_path.to_str().unwrap(),
        None,
        vec!["http".to_string()],
    )
    .unwrap();

    let http_block = root_ctx
        .children
        .iter()
        .find(|child| child.block_name.trim() == "http")
        .expect("http block not found");

    let mut http_manager = HttpManager::new(http_block);
    http_manager.start();
    http_manager.join();

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
