use std::path::Path;
use std::thread;
use std::time::Duration;

use blur::core::config::config_loader;
use blur::core::config::storage::{get_default_storage_path, FileStorage, Storage};
use blur::{core::config::config_manager::ConfigManager, http::http_manager::HttpManager};

fn main() {
    ConfigManager::init();

    let config_path = "/home/yuwhisper/projects/blur/config/config_template";
    let storage_path = get_default_storage_path();
    println!("Storage path: {:?}", storage_path);
    let storage_path = storage_path.to_str().unwrap();

    let storage;
    if !Path::new(storage_path).exists() {
        storage = FileStorage::open(storage_path).expect("Failed to open file storage");
        config_loader::load_config_file(config_path, &storage).unwrap();
    } else {
        storage = FileStorage::open(storage_path).expect("Failed to open file storage");
        let check = storage.read_file("a").unwrap();
        println!("{:?}", String::from_utf8(check));
    }

    let root_ctx = config_loader::process_existing_config(&storage).unwrap();

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
