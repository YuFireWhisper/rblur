use crate::core::config::config_context::ConfigContext;
use crate::core::config::config_manager::ConfigManager;
use serde_json::{json, Map, Value};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug)]
pub enum ConfigError {
    IoError(io::Error),
    JsonError(serde_json::Error),
    ValidationError(String),
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::IoError(e)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError::JsonError(e)
    }
}

/// 對 JSON 進行合併，對於物件採用遞迴合併；對於陣列（代表非唯一的塊），
/// 若模板陣列非空，則以模板第一個元素為基礎，對 user 陣列中每個項目分別合併。
fn merge_config(template: &Value, user: &Value) -> Value {
    match (template, user) {
        (Value::Object(t_map), Value::Object(u_map)) => {
            let mut merged = t_map.clone();
            for (k, u_val) in u_map {
                if let Some(t_val) = t_map.get(k) {
                    merged.insert(k.clone(), merge_config(t_val, u_val));
                } else {
                    merged.insert(k.clone(), u_val.clone());
                }
            }
            Value::Object(merged)
        }
        (Value::Array(t_arr), Value::Array(u_arr)) if !t_arr.is_empty() => {
            let default_item = &t_arr[0];
            let mut merged_arr = Vec::new();
            if u_arr.is_empty() {
                merged_arr = t_arr.clone();
            } else {
                for u_item in u_arr {
                    merged_arr.push(merge_config(default_item, u_item));
                }
            }
            Value::Array(merged_arr)
        }
        (_, u_val) => u_val.clone(),
    }
}

/// 解析配置文件（類 Nginx 語法）的文字內容，並轉換為 JSON 結構。
fn parse_nginx_config(file_path: &str) -> Result<Value, ConfigError> {
    let content = fs::read_to_string(file_path)?;
    let tokens = tokenize(&content);
    let (nodes, _) = parse_tokens(&tokens, 0)?;
    let json_value = nodes_to_json(&nodes);
    Ok(json_value)
}

/// 定義解析器用的 Token 類型
#[derive(Debug, Clone)]
enum Token {
    Word(String),
    LBrace,
    RBrace,
    Semicolon,
}

/// 將輸入文字斷詞為 Token 列表
fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut pos = 0;
    let bytes = input.as_bytes();
    while pos < bytes.len() {
        // 略過空白與註解
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }
        if bytes[pos] == b'#' {
            while pos < bytes.len() && bytes[pos] != b'\n' {
                pos += 1;
            }
            continue;
        }
        match bytes[pos] {
            b'{' => {
                tokens.push(Token::LBrace);
                pos += 1;
            }
            b'}' => {
                tokens.push(Token::RBrace);
                pos += 1;
            }
            b';' => {
                tokens.push(Token::Semicolon);
                pos += 1;
            }
            _ => {
                let start = pos;
                while pos < bytes.len()
                    && !bytes[pos].is_ascii_whitespace()
                    && bytes[pos] != b'{'
                    && bytes[pos] != b'}'
                    && bytes[pos] != b';'
                {
                    pos += 1;
                }
                let word = String::from_utf8_lossy(&bytes[start..pos]).to_string();
                tokens.push(Token::Word(word));
            }
        }
    }
    tokens
}

/// 代表解析後的配置節點
#[derive(Debug)]
struct ConfigNode {
    command: String,
    args: Vec<String>,
    children: Vec<ConfigNode>,
}

/// 遞迴解析 Token，返回 ConfigNode 列表及新位置
fn parse_tokens(tokens: &[Token], mut pos: usize) -> Result<(Vec<ConfigNode>, usize), ConfigError> {
    let mut nodes = Vec::new();
    while pos < tokens.len() {
        match &tokens[pos] {
            Token::RBrace => {
                pos += 1;
                break;
            }
            Token::Word(cmd) => {
                pos += 1;
                let mut args = Vec::new();
                let mut children = Vec::new();
                while pos < tokens.len() {
                    match &tokens[pos] {
                        Token::Semicolon => {
                            pos += 1;
                            break;
                        }
                        Token::LBrace => {
                            pos += 1;
                            let (child_nodes, new_pos) = parse_tokens(tokens, pos)?;
                            children = child_nodes;
                            pos = new_pos;
                            break;
                        }
                        Token::RBrace => {
                            break;
                        }
                        Token::Word(arg) => {
                            args.push(arg.clone());
                            pos += 1;
                        }
                    }
                }
                nodes.push(ConfigNode {
                    command: cmd.clone(),
                    args,
                    children,
                });
            }
            Token::LBrace => {
                pos += 1;
                let (child_nodes, new_pos) = parse_tokens(tokens, pos)?;
                nodes.extend(child_nodes);
                pos = new_pos;
            }
            Token::Semicolon => {
                pos += 1;
            }
        }
    }
    Ok((nodes, pos))
}

/// 將解析後的 ConfigNode 樹轉換為 JSON 結構，採用 ConfigManager 提供的模板進行覆蓋。
fn nodes_to_json(nodes: &[ConfigNode]) -> Value {
    let mut map = Map::new();
    for node in nodes {
        if let Some(cmd) = crate::core::config::config_manager::get_command(&node.command) {
            let mut node_json = if cmd.is_block {
                ConfigManager::get_block_template(&node.command, false).unwrap_or_else(|| json!({}))
            } else {
                ConfigManager::get_block_template(&node.command, false).unwrap_or_else(|| json!({}))
            };
            // 將解析到的參數依序覆蓋預設值
            if let Some(Value::Array(arr)) = node_json.get_mut("params") {
                for (i, arg) in node.args.iter().enumerate() {
                    if let Some(param_obj) = arr.get_mut(i).and_then(|v| v.as_object_mut()) {
                        param_obj.insert("value".to_string(), Value::String(arg.clone()));
                    }
                }
            }

            // 處理子節點
            if !node.children.is_empty() {
                let children_json = nodes_to_json(&node.children);
                node_json
                    .as_object_mut()
                    .unwrap()
                    .insert("children".to_string(), children_json);
            }
            // 將此節點放入結果中：若非唯一則以陣列形式呈現
            if cmd.unique {
                map.insert(node.command.clone(), node_json);
            } else {
                map.entry(node.command.clone())
                    .and_modify(|e| {
                        if let Value::Array(arr) = e {
                            arr.push(node_json.clone());
                        }
                    })
                    .or_insert_with(|| Value::Array(vec![node_json]));
            }
        }
    }
    Value::Object(map)
}

/// 遞迴處理最終配置 JSON，建立 ConfigContext 樹。  
/// - 若指令為塊，呼叫 new_empty 建立新塊並呼叫其 handler，再處理 children；  
/// - 若非塊，則寫入當前上下文並呼叫 handler。
fn process_final_config(config: &Value, parent_ctx: &mut ConfigContext) -> Result<(), ConfigError> {
    if let Value::Object(map) = config {
        for (key, value) in map {
            if let Some(cmd) = crate::core::config::config_manager::get_command(key) {
                if cmd.is_block {
                    if cmd.unique {
                        if let Value::Object(obj) = value {
                            let args = extract_args(obj);
                            let mut child_ctx = ConfigContext::new_empty(key, args);
                            cmd.handle(&mut child_ctx, value);
                            if let Some(children) = obj.get("children") {
                                process_final_config(children, &mut child_ctx)?;
                            }
                            parent_ctx.children.push(child_ctx);
                        } else if let Value::Array(arr) = value {
                            if arr.len() == 1 {
                                if let Value::Object(obj) = &arr[0] {
                                    let args = extract_args(obj);
                                    let mut child_ctx = ConfigContext::new_empty(key, args);
                                    cmd.handle(&mut child_ctx, &arr[0]);
                                    if let Some(children) = obj.get("children") {
                                        process_final_config(children, &mut child_ctx)?;
                                    }
                                    parent_ctx.children.push(child_ctx);
                                }
                            } else {
                                return Err(ConfigError::ValidationError(format!(
                                    "Unique command {} must have exactly one instance",
                                    key
                                )));
                            }
                        } else {
                            return Err(ConfigError::ValidationError(format!(
                                "Invalid format for unique command: {}",
                                key
                            )));
                        }
                    } else if let Value::Array(arr) = value {
                        for item in arr {
                            if let Value::Object(obj) = item {
                                let args = extract_args(obj);
                                let mut child_ctx = ConfigContext::new_empty(key, args);
                                cmd.handle(&mut child_ctx, item);
                                if let Some(children) = obj.get("children") {
                                    process_final_config(children, &mut child_ctx)?;
                                }
                                parent_ctx.children.push(child_ctx);
                            }
                        }
                    } else {
                        return Err(ConfigError::ValidationError(format!(
                            "Non-unique command {} must be in an array",
                            key
                        )));
                    }
                } else {
                    // 非塊指令，直接寫入當前上下文
                    if let Value::Object(obj) = value {
                        let args = extract_args(obj);
                        if args.iter().all(|arg| arg.is_empty()) {
                            continue;
                        }
                        parent_ctx.current_cmd_name = key.clone();
                        parent_ctx.current_cmd_args = args;
                        cmd.handle(parent_ctx, value);
                        if let Some(children) = obj.get("children") {
                            process_final_config(children, parent_ctx)?;
                        }
                    } else if let Value::Array(arr) = value {
                        if arr.len() == 1 {
                            if let Value::Object(obj) = &arr[0] {
                                let args = extract_args(obj);
                                if args.iter().all(|arg| arg.is_empty()) {
                                    continue;
                                }
                                parent_ctx.current_cmd_name = key.clone();
                                parent_ctx.current_cmd_args = args;
                                cmd.handle(parent_ctx, &arr[0]);
                                if let Some(children) = obj.get("children") {
                                    process_final_config(children, parent_ctx)?;
                                }
                            }
                        } else {
                            return Err(ConfigError::ValidationError(format!(
                                "Non-unique command {} must be in an array with one element",
                                key
                            )));
                        }
                    }
                }
            } else {
                return Err(ConfigError::ValidationError(format!(
                    "Unknown command: {}",
                    key
                )));
            }
        }
    }
    Ok(())
}

/// 輔助函式：從物件中讀取 "params" 欄位，並依序取出每個參數的 "value" 作為字串集合
fn extract_args(obj: &Map<String, Value>) -> Vec<String> {
    if let Some(Value::Array(params)) = obj.get("params") {
        params
            .iter()
            .map(|param| {
                param
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            })
            .collect()
    } else {
        Vec::new()
    }
}

/// 主 API：
/// - storage_path: 存儲 JSON 配置的檔案路徑  
/// - config_file: 可選的配置文件（nginx 語法）路徑  
/// - top_blocks: 頂層塊名稱集合（例如 ["http"]）  
///
/// 傳回代表當前配置的 ConfigContext 根節點。
pub fn load_config(
    storage_path: &str,
    config_file: Option<&str>,
    top_blocks: Vec<String>,
) -> Result<ConfigContext, ConfigError> {
    // 1. 從 ConfigManager 取得完整模板
    let complete_template =
        ConfigManager::get_complete_template(top_blocks).map_err(ConfigError::ValidationError)?;

    // 2. 若有配置文件則解析；否則嘗試讀取存儲的 JSON
    let file_config = if let Some(path) = config_file {
        Some(parse_nginx_config(path)?)
    } else {
        None
    };

    let stored_config = if Path::new(storage_path).exists() {
        let content = fs::read_to_string(storage_path)?;
        Some(serde_json::from_str(&content)?)
    } else {
        None
    };

    // 3. 判斷使用哪一組配置：有配置文件則優先使用；否則使用存儲；若都無，則以空物件表示
    let user_config = if let Some(fc) = file_config {
        fc
    } else if let Some(sc) = stored_config {
        sc
    } else {
        json!({})
    };

    // 4. 以模板為基礎，合併使用者配置
    let final_config = merge_config(&complete_template, &user_config);

    // 5. 將最終配置寫回存儲（持久化）
    fs::write(storage_path, serde_json::to_string_pretty(&final_config)?)?;

    // 6. 依據最終配置處理並建立 ConfigContext 樹
    let mut root_ctx = ConfigContext::new_empty("root", vec![]);
    process_final_config(&final_config, &mut root_ctx)?;

    Ok(root_ctx)
}
