use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use crate::core::config::command::Command;

pub static REGISTERED_COMMANDS: OnceLock<Mutex<HashMap<String, Arc<Command>>>> = OnceLock::new();

fn get_registry() -> MutexGuard<'static, HashMap<String, Arc<Command>>> {
    REGISTERED_COMMANDS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

fn param_to_json(p: &crate::core::config::command::Parameter) -> Value {
    json!({
        "index": p.index,
        "display_name": p.display_name,
        "type": p.type_name,
        "is_required": p.is_required,
        "default": p.default,
        "value": p.default,
        "desc": p.desc,
    })
}

fn command_to_json(
    cmd: &Command,
    recursive: bool,
    registry: &HashMap<String, Arc<Command>>,
) -> Value {
    let mut obj = json!({
        "is_block": cmd.is_block,
        "unique": cmd.unique,
        "display_name": cmd.display_name,
        "desc": cmd.desc,
        "params": cmd.params.iter().map(param_to_json).collect::<Vec<Value>>()
    });

    if cmd.is_block && recursive {
        let children = build_children_template(registry, &cmd.name, recursive);
        obj.as_object_mut()
            .unwrap()
            .insert("children".to_string(), children);
    }
    obj
}

pub fn register_command(cmd: Command) {
    let mut reg = get_registry();
    if reg.contains_key(&cmd.name) {
        panic!("Command {} is already registered", cmd.name);
    }
    reg.insert(cmd.name.clone(), Arc::new(cmd));
}

pub fn get_command(name: &str) -> Option<Arc<Command>> {
    let reg = get_registry();
    reg.get(name).cloned()
}

pub fn get_block_json(block_name: &str, recursive: bool) -> Option<Value> {
    let reg = get_registry();
    reg.get(block_name)
        .map(|cmd| command_to_json(cmd, recursive, &reg))
}

fn build_children_template(
    registry: &HashMap<String, Arc<Command>>,
    parent: &str,
    recursive: bool,
) -> Value {
    let mut children_map = serde_json::Map::new();

    for cmd in registry.values() {
        if cmd.allowed_parents.contains(&parent.to_string()) {
            let child_json = command_to_json(cmd, recursive, registry);
            if cmd.unique {
                children_map.insert(cmd.name.clone(), child_json);
            } else {
                children_map
                    .entry(cmd.name.clone())
                    .and_modify(|e| {
                        if let Value::Array(arr) = e {
                            arr.push(child_json.clone());
                        }
                    })
                    .or_insert_with(|| Value::Array(vec![child_json]));
            }
        }
    }
    Value::Object(children_map)
}

pub struct ConfigManager;

impl ConfigManager {
    pub fn get_complete_template(top_blocks: Vec<String>) -> Result<Value, String> {
        let reg = get_registry();
        let mut map = serde_json::Map::new();

        for block in top_blocks {
            let cmd = reg
                .get(&block)
                .ok_or_else(|| format!("Block {} not registered", block))?;
            let template = get_block_json(&block, true)
                .ok_or_else(|| format!("No template for block {}", block))?;

            let final_template = if !cmd.unique {
                match template {
                    Value::Object(_) => Value::Array(vec![template]),
                    Value::Array(arr) if arr.is_empty() => Value::Array(vec![json!({})]),
                    Value::Array(arr) => Value::Array(arr),
                    other => other,
                }
            } else {
                template
            };

            map.insert(block, final_template);
        }
        Ok(Value::Object(map))
    }

    pub fn get_block_template(block_name: &str, recursive: bool) -> Option<Value> {
        get_block_json(block_name, recursive)
    }
}

pub fn bool_str_to_bool(value: &str) -> Result<bool, String> {
    match value.to_lowercase().as_str() {
        "on" | "true" => Ok(true),
        "off" | "false" => Ok(false),
        _ => Err(format!("Invalid boolean value: {}", value)),
    }
}

pub fn get_config_param(config: &Value, index: usize) -> Option<String> {
    config
        .get("params")
        .and_then(|arr| arr.as_array())
        .and_then(|arr| arr.get(index))
        .and_then(|param| param.get("value"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
