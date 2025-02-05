use std::{any::TypeId, sync::atomic::AtomicPtr};

#[derive(Debug)]
pub struct ConfigContext {
    pub block_name: String,
    pub block_args: Vec<String>,
    pub current_cmd_name: String,
    pub current_cmd_args: Vec<String>,
    pub current_block_type_id: Option<TypeId>,
    pub current_ctx: Option<AtomicPtr<u8>>,
    pub spare1: Option<AtomicPtr<u8>>,
    pub spare2: Option<AtomicPtr<u8>>,
    pub spare3: Option<AtomicPtr<u8>>,
    pub spare4: Option<AtomicPtr<u8>>,
    pub spare5: Option<AtomicPtr<u8>>,
    pub parse_pos: u64,
    pub children: Vec<ConfigContext>,
}

impl ConfigContext {
    pub fn new_empty(block_name: String, args: Vec<String>) -> Self {
        ConfigContext {
            block_name,
            block_args: args,
            current_cmd_name: String::new(),
            current_cmd_args: Vec::new(),
            current_block_type_id: None,
            current_ctx: None,
            spare1: None,
            spare2: None,
            spare3: None,
            spare4: None,
            spare5: None,
            parse_pos: 0,
            children: Vec::new(),
        }
    }
}
