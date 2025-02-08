use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::core::config::command::Command;

/// 全局指令註冊表，使用 HashMap 以指令名稱作為 key
pub static REGISTERED_COMMANDS: OnceLock<Mutex<HashMap<String, Arc<Command>>>> =
    OnceLock::new();

/// 註冊指令：若同名指令已存在則 panic（指令定義預期在整個應用中唯一）
pub fn register_command(cmd: Command) {
    let registry = REGISTERED_COMMANDS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut reg = registry.lock().unwrap();
    if reg.contains_key(&cmd.name) {
        panic!("Command {} is already registered", cmd.name);
    }
    reg.insert(cmd.name.clone(), Arc::new(cmd));
}

/// 取得指令的參考（若不存在則回傳 None）
pub fn get_command(name: &str) -> Option<Arc<Command>> {
    let registry = REGISTERED_COMMANDS.get_or_init(|| Mutex::new(HashMap::new()));
    let reg = registry.lock().unwrap();
    reg.get(name).cloned()
}

/// 取得指定塊（block）的 JSON 樣板：
/// - 傳入 block_name 與 recursive flag（是否包含所有子塊）
/// - 若指令為塊，會將各參數預設值寫入，並且如果 recursive 為 true 時，則遞迴產生 children
pub fn get_block_json(block_name: &str, recursive: bool) -> Option<Value> {
    let registry = REGISTERED_COMMANDS.get_or_init(|| Mutex::new(HashMap::new()));
    let reg = registry.lock().unwrap();
    reg.get(block_name).map(|cmd| {
        let mut obj = json!({
            "is_block": cmd.is_block,
            "unique": cmd.unique,
            "display_name": cmd.display_name,
            "desc": cmd.desc,
            "params": cmd.params.iter().map(|p| {
                json!({
                    "index": p.index,
                    "display_name": p.display_name,
                    "type": p.type_name,
                    "is_required": p.is_required,
                    "default": p.default,
                    "value": p.default, // 初始值先設為預設值
                    "desc": p.desc,
                })
            }).collect::<Vec<Value>>()
        });
        if cmd.is_block && recursive {
            // 取得此塊下允許出現的所有子指令樣板
            let children = build_children_template(&reg, &cmd.name, recursive);
            obj.as_object_mut()
                .unwrap()
                .insert("children".to_string(), children);
        }
        obj
    })
}

/// 根據上層指令名稱，遞迴建立 children 模板
fn build_children_template(
    reg: &HashMap<String, Arc<Command>>,
    parent: &str,
    recursive: bool,
) -> Value {
    let mut children_map = serde_json::Map::new();
    for cmd in reg.values() {
        if cmd.allowed_parents.contains(&parent.to_string()) {
            let mut obj = json!({
                "is_block": cmd.is_block,
                "unique": cmd.unique,
                "display_name": cmd.display_name,
                "desc": cmd.desc,
                "params": cmd.params.iter().map(|p| {
                    json!({
                        "index": p.index,
                        "display_name": p.display_name,
                        "type": p.type_name,
                        "is_required": p.is_required,
                        "default": p.default,
                        "value": p.default,
                        "desc": p.desc,
                    })
                }).collect::<Vec<Value>>()
            });
            if cmd.is_block && recursive {
                let children = build_children_template(reg, &cmd.name, recursive);
                obj.as_object_mut()
                    .unwrap()
                    .insert("children".to_string(), children);
            }
            // 若該塊在同一區域內為唯一則以物件儲存，否則使用陣列以避免重複鍵錯誤
            if cmd.unique {
                children_map.insert(cmd.name.clone(), obj);
            } else {
                children_map
                    .entry(cmd.name.clone())
                    .and_modify(|e| {
                        if let Value::Array(arr) = e {
                            arr.push(obj.clone());
                        }
                    })
                    .or_insert_with(|| Value::Array(vec![obj]));
            }
        }
    }
    Value::Object(children_map)
}

/// ConfigManager 提供額外的 API，例如根據塊名稱與是否要包含子塊來取得樣板，以及取得完整模板。
pub struct ConfigManager;

impl ConfigManager {
    pub fn init() {
        // 可在此補充初始化邏輯
    }

    /// 根據傳入的頂層塊名稱產生完整模板（包含遞迴下的所有子塊），
    /// 若塊為非唯一則以陣列形式表示（並確保至少有一個預設值）。
    pub fn get_complete_template(top_blocks: Vec<String>) -> Result<Value, String> {
        let mut map = serde_json::Map::new();
        for block in top_blocks {
            if let Some(template) = get_block_json(&block, true) {
                // 若該塊非唯一，確保以陣列呈現
                let registry = REGISTERED_COMMANDS.get_or_init(|| Mutex::new(HashMap::new()));
                let reg = registry.lock().unwrap();
                if let Some(cmd) = reg.get(&block) {
                    if !cmd.unique {
                        match template {
                            Value::Object(_) => {
                                map.insert(block, Value::Array(vec![template]));
                            }
                            Value::Array(arr) => {
                                if arr.is_empty() {
                                    map.insert(block, Value::Array(vec![json!({})]));
                                } else {
                                    map.insert(block, Value::Array(arr));
                                }
                            }
                            _ => {
                                map.insert(block, template);
                            }
                        }
                    } else {
                        map.insert(block, template);
                    }
                } else {
                    return Err(format!("Block {} not registered", block));
                }
            } else {
                return Err(format!("No template for block {}", block));
            }
        }
        Ok(Value::Object(map))
    }

    /// 取得單一塊的模板（僅依照預設值產生，不含使用者覆蓋部分）
    pub fn get_block_template(block_name: &str, recursive: bool) -> Option<Value> {
        get_block_json(block_name, recursive)
    }
}

/// 輔助函式：將類似 "on"/"off" 或 "true"/"false" 的字串轉為 bool 值。
pub fn bool_str_to_bool(value: &str) -> Result<bool, String> {
    match value.to_lowercase().as_str() {
        "on" | "true" => Ok(true),
        "off" | "false" => Ok(false),
        _ => Err(format!("Invalid boolean value: {}", value)),
    }
}

/// 取得配置中指定索引的參數值（字串）
/// 此函式名稱採用 get_config_parame 與舊版相符
pub fn get_config_parame(config: &Value, index: usize) -> Option<String> {
    config
        .get("params")
        .and_then(|arr| arr.as_array())
        .and_then(|arr| arr.get(index))
        .and_then(|param| param.get("value"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

