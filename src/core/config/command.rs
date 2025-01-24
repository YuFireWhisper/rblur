use std::any::TypeId;

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
