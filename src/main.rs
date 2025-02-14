use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use clap::Parser;
use rblur::http::http_server::get_default_storage_path;
use rblur::{core::config::config_loader, http::http_manager::HttpManager};
use std::env;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(
        short,
        long,
        value_name = "CONFIG FILE PATH",
        conflicts_with = "use_default_config"
    )]
    config_path: Option<String>,

    #[arg(short, long, value_name = "USE DEFAULT CONFIG")]
    use_default_config: bool,
}

fn main() {
    let args = Args::parse();
    let storage_path = get_default_storage_path();

    let config_path = if args.use_default_config {
        let mut cargo_manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        cargo_manifest_dir.push("config");
        cargo_manifest_dir.push("default");
        Some(cargo_manifest_dir.into_os_string().into_string().unwrap())
    } else {
        args.config_path
    };

    let root_ctx = match config_loader::load_config(
        storage_path.to_str().unwrap(),
        config_path.as_deref(),
        vec!["http".to_string()],
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            return;
        }
    };

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
