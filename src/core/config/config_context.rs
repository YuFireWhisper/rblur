use std::{
    any::TypeId,
    sync::atomic::{AtomicPtr, Ordering},
};

type BlockEndCallback = Box<dyn FnOnce(&mut ConfigContext) + Send + Sync>;

#[derive(Default)]
pub struct ConfigContext {
    pub current_cmd_name: String,
    pub current_cmd_args: Vec<String>,
    pub current_block_type_id: Option<TypeId>,
    pub current_ctx: Option<AtomicPtr<u8>>,
    pub block_end_callback: Option<BlockEndCallback>,
    pub spare1: Option<AtomicPtr<u8>>,
    pub spare2: Option<AtomicPtr<u8>>,
    pub spare3: Option<AtomicPtr<u8>>,
    pub spare4: Option<AtomicPtr<u8>>,
    pub spare5: Option<AtomicPtr<u8>>,
}

impl ConfigContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clone_current_ctx(&self) -> Option<AtomicPtr<u8>> {
        self.current_ctx
            .as_ref()
            .map(|p| AtomicPtr::new(p.load(Ordering::SeqCst)))
    }
}
