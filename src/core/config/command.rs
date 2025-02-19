use crate::core::config::config_context::ConfigContext;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Parameter {
    pub index: usize,
    pub display_name: HashMap<String, String>,
    pub type_name: String,
    pub is_required: bool,
    pub default: String,
    pub desc: HashMap<String, String>,
}

impl Parameter {
    pub fn new(
        index: usize,
        display_name: HashMap<String, String>,
        type_name: &str,
        is_required: bool,
        default: &str,
        desc: HashMap<String, String>,
    ) -> Self {
        Parameter {
            index,
            display_name,
            type_name: type_name.to_string(),
            is_required,
            default: default.to_string(),
            desc,
        }
    }
}

pub struct ParameterBuilder {
    index: usize,
    display_name: HashMap<String, String>,
    type_name: String,
    is_required: bool,
    default: String,
    desc: HashMap<String, String>,
}

impl ParameterBuilder {
    pub fn new(index: usize) -> Self {
        Self {
            index,
            display_name: HashMap::new(),
            type_name: "".to_string(),
            is_required: false,
            default: "".to_string(),
            desc: HashMap::new(),
        }
    }

    pub fn display_name(mut self, lang: &str, name: &str) -> Self {
        self.display_name.insert(lang.to_string(), name.to_string());
        self
    }

    pub fn type_name(mut self, type_name: &str) -> Self {
        self.type_name = type_name.to_string();
        self
    }

    pub fn is_required(mut self, is_required: bool) -> Self {
        self.is_required = is_required;
        self
    }

    pub fn default(mut self, default: &str) -> Self {
        self.default = default.to_string();
        self
    }

    pub fn desc(mut self, lang: &str, desc: &str) -> Self {
        self.desc.insert(lang.to_string(), desc.to_string());
        self
    }

    pub fn build(self) -> Parameter {
        Parameter {
            index: self.index,
            display_name: self.display_name,
            type_name: self.type_name,
            is_required: self.is_required,
            default: self.default,
            desc: self.desc,
        }
    }
}

type CommandHandler = Box<dyn Fn(&mut ConfigContext, &Value) + Send + Sync>;

pub struct Command {
    pub name: String,
    pub is_block: bool,
    pub unique: bool,
    pub allowed_parents: Vec<String>,
    pub display_name: HashMap<String, String>,
    pub desc: HashMap<String, String>,
    pub params: Vec<Parameter>,
    pub handler: CommandHandler,
}

impl Command {
    pub fn handle(&self, ctx: &mut ConfigContext, config: &Value) {
        (self.handler)(ctx, config);
    }
}

pub struct CommandBuilder {
    name: String,
    is_block: bool,
    unique: bool,
    allowed_parents: Vec<String>,
    display_name: HashMap<String, String>,
    desc: HashMap<String, String>,
    params: Vec<Parameter>,
}

impl CommandBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            is_block: false,
            unique: false,
            allowed_parents: vec![],
            display_name: HashMap::new(),
            desc: HashMap::new(),
            params: vec![],
        }
    }

    pub fn is_block(mut self) -> Self {
        self.is_block = true;
        self
    }

    pub fn is_unique(mut self) -> Self {
        self.unique = true;
        self
    }

    pub fn allowed_parents(mut self, parents: Vec<String>) -> Self {
        self.allowed_parents = parents;
        self
    }

    pub fn display_name(mut self, lang: &str, name: &str) -> Self {
        self.display_name.insert(lang.to_string(), name.to_string());
        self
    }

    pub fn desc(mut self, lang: &str, desc: &str) -> Self {
        self.desc.insert(lang.to_string(), desc.to_string());
        self
    }

    pub fn params(mut self, params: Vec<Parameter>) -> Self {
        self.params = params;
        self
    }

    pub fn build<F>(self, handler: F) -> Command
    where
        F: Fn(&mut ConfigContext, &Value) + Send + Sync + 'static,
    {
        Command {
            name: self.name,
            is_block: self.is_block,
            unique: self.unique,
            allowed_parents: self.allowed_parents,
            display_name: self.display_name,
            desc: self.desc,
            params: self.params,
            handler: Box::new(handler),
        }
    }
}

#[macro_export]
macro_rules! register_commands {
    ($($cmd:expr),+ $(,)?) => {
        $(
            const _: () = {
                #[used]
                #[link_section = ".init_array"]
                static REGISTER_: extern "C" fn() = {
                    extern "C" fn init() {
                        let registry = $crate::core::config::config_manager::REGISTERED_COMMANDS
                            .get_or_init(|| {
                                std::sync::Mutex::new(std::collections::HashMap::new())
                            });
                        if let Ok(mut commands) = registry.lock() {
                            commands.insert(
                                $cmd.name.to_string(),
                                std::sync::Arc::new($cmd),
                            );
                        }
                    }
                    init
                };
            };
        )*
    };
}
