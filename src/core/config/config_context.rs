use std::{any::TypeId, fs::File, io::BufReader, sync::atomic::AtomicPtr};

pub struct ConfigContext {
    pub current_cmd_name: String,
    pub current_cmd_args: Vec<String>,
    pub current_block_type_id: Option<TypeId>,
    pub current_ctx: Option<AtomicPtr<u8>>,
    pub spare1: Option<AtomicPtr<u8>>,
    pub spare2: Option<AtomicPtr<u8>>,
    pub spare3: Option<AtomicPtr<u8>>,
    pub spare4: Option<AtomicPtr<u8>>,
    pub spare5: Option<AtomicPtr<u8>>,
    pub reader: BufReader<File>,
    pub parse_pos: u64,
}

impl ConfigContext {
    pub fn new(path: &str) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        Ok(ConfigContext {
            current_cmd_name: String::new(),
            current_cmd_args: Vec::new(),
            current_block_type_id: None,
            current_ctx: None,
            spare1: None,
            spare2: None,
            spare3: None,
            spare4: None,
            spare5: None,
            reader,
            parse_pos: 0,
        })
    }
}
