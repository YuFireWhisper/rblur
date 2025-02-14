use std::thread;
use std::time::Duration;

use blur::http::http_server::get_default_storage_path;
use blur::{core::config::config_loader, http::http_manager::HttpManager};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_name = "FILE")]
    config_path: Option<String>,
}

fn main() {
    let args = Args::parse();

    let storage_path = get_default_storage_path();

    let root_ctx = config_loader::load_config(
        storage_path.to_str().unwrap(),
        args.config_path.as_deref(), // Convert Option<String> to Option<&str>
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
