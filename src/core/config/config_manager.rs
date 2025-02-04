use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

use thiserror::Error;

use super::command::Command;

static REGISTERED_COMMANDS: OnceLock<Mutex<Vec<Command>>> = OnceLock::new();
static CONFIG_MANAGER: OnceLock<ConfigManager> = OnceLock::new();

#[doc(hidden)]
pub fn commands_registry() -> &'static Mutex<Vec<Command>> {
    REGISTERED_COMMANDS.get_or_init(|| Mutex::new(Vec::new()))
}

pub struct ConfigManager {
    commands: HashMap<String, Command>,
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
            commands,
        });
    }

    pub fn instance() -> &'static ConfigManager {
        CONFIG_MANAGER.get().expect("ConfigManager not initialized")
    }

    pub fn get_command(name: &str) -> Option<&'static Command> {
        Self::instance().commands.get(name)
    }
}

#[derive(Debug, Error)]
pub enum SetFieldError {
    #[error("Invalid value for bool field: {0}")]
    InvalidBoolValue(String),
    #[error("Invalid value for field: {0}")]
    InvalidValue(String),
}

pub fn set_field<T, U: FromStr>(
    target: &mut T,
    field_accessor: impl FnOnce(&mut T) -> &mut U,
    value: &str,
) -> Result<(), SetFieldError> {
    let field = field_accessor(target);
    *field = value
        .parse::<U>()
        .map_err(|_| SetFieldError::InvalidValue(value.to_string()))?;
    Ok(())
}

pub fn bool_str_to_bool(value: &str) -> Result<bool, SetFieldError> {
    match value.to_lowercase().as_str() {
        "on" | "true" => Ok(true),
        "off" | "false" => Ok(false),
        _ => Err(SetFieldError::InvalidBoolValue(value.to_string())),
    }
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
