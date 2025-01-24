use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use super::command::Command;

static REGISTERED_COMMANDS: OnceLock<Mutex<Vec<Command>>> = OnceLock::new();
static CONFIG_MANAGER: OnceLock<ConfigManager> = OnceLock::new();

#[doc(hidden)]
pub fn commands_registry() -> &'static Mutex<Vec<Command>> {
    REGISTERED_COMMANDS.get_or_init(|| Mutex::new(Vec::new()))
}

pub struct ConfigManager {
    commands: Arc<HashMap<String, Command>>,
}

#[macro_export]
macro_rules! register_commands {
    ($cmd:expr) => {
        #[used]
        #[link_section = ".init_array"]
        static REGISTER: extern "C" fn() = {
            extern "C" fn init() {
                let registry = $crate::commands_registry();
                if let Ok(mut commands) = registry.lock() {
                    commands.push($cmd);
                }
            }
            init
        };
    };

    ($($cmd:expr),+ $(,)?) => {
        #[used]
        #[link_section = ".init_array"]
        static REGISTER: extern "C" fn() = {
            extern "C" fn init() {
                let registry = &$crate::core::config::config_manager::commands_registry();
                if let Ok(mut commands) = registry.lock() {
                    $(
                        commands.push($cmd);
                    )+
                }
            }
            init
        };
    };
}

#[macro_export]
macro_rules! get_command {
    ($name:expr) => {
        ConfigManager::get_command($name)
    };
}

impl ConfigManager {
    pub fn init() {
        let registry = commands_registry();
        let commands = if let Ok(mut registered_commands) = registry.lock() {
            let mut command_map = HashMap::new();
            for cmd in registered_commands.drain(..) {
                command_map.insert(cmd.cmd_name.clone(), cmd);
            }
            command_map
        } else {
            HashMap::new()
        };

        let _ = CONFIG_MANAGER.set(ConfigManager {
            commands: Arc::new(commands),
        });
    }

    pub fn instance() -> &'static ConfigManager {
        CONFIG_MANAGER.get().expect("ConfigManager not initialized")
    }

    pub fn get_command(name: &str) -> Option<&'static Command> {
        Self::instance().commands.get(name)
    }
}
