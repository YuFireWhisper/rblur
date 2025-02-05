use crate::core::config::config_manager::ConfigManager;
use std::any::TypeId;

use crate::get_command;

use super::config_context::ConfigContext;

pub struct Command {
    pub cmd_name: String,
    pub cmd_valid_block: Vec<TypeId>,
    pub cmd_set: Box<dyn Fn(&mut ConfigContext) + Send + Sync>,
}

impl Command {
    pub fn new<F>(name: &str, valid_block: Vec<TypeId>, set_fn: F) -> Self
    where
        F: Fn(&mut ConfigContext) + Send + Sync + 'static,
    {
        Command {
            cmd_name: name.to_string(),
            cmd_valid_block: valid_block,
            cmd_set: Box::new(set_fn),
        }
    }
}

pub fn handle_command(ctx: &mut ConfigContext, is_block: bool) {
    let cmd_name = {
        if is_block {
            ctx.block_name.trim()
        } else {
            ctx.current_cmd_name.trim()
        }
    };
    println!("處理指令: {}", cmd_name);
    if let Some(cmd) = get_command!(cmd_name) {
        if let Some(type_id) = ctx.current_block_type_id {
            if !cmd.cmd_valid_block.contains(&type_id) && !cmd.cmd_valid_block.is_empty() {
                panic!("Command in wrong block");
            }
        }
        (cmd.cmd_set)(ctx);
    } else {
        eprintln!("Unknown command: {}", cmd_name);
    }
}
