use crate::core::config::config_context::ConfigContext;
use crate::core::config::config_manager::ConfigManager;
use serde_json::{json, Map, Value};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

use super::command::Command;
use super::config_manager::get_command;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Validation error: {0}")]
    ValidationError(String),
}

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

fn parse_nginx_config(file_path: &str) -> Result<Value, ConfigError> {
    let content = fs::read_to_string(file_path)?;
    let tokens = tokenize(&content);
    let (nodes, _) = parse_tokens(&tokens, 0)?;
    let json_value = nodes_to_json(&nodes);
    Ok(json_value)
}

#[derive(Debug, Clone)]
enum Token {
    Word(String),
    LBrace,
    RBrace,
    Semicolon,
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut pos = 0;
    let bytes = input.as_bytes();
    while pos < bytes.len() {
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

#[derive(Debug)]
struct ConfigNode {
    command: String,
    args: Vec<String>,
    children: Vec<ConfigNode>,
}

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

fn nodes_to_json(nodes: &[ConfigNode]) -> Value {
    let mut map = Map::new();
    for node in nodes {
        if let Some(cmd) = get_command(&node.command) {
            let mut node_json = if cmd.is_block {
                ConfigManager::get_block_template(&node.command, false).unwrap_or_else(|| json!({}))
            } else {
                ConfigManager::get_block_template(&node.command, false).unwrap_or_else(|| json!({}))
            };

            if let Some(Value::Array(arr)) = node_json.get_mut("params") {
                for (i, arg) in node.args.iter().enumerate() {
                    if let Some(param_obj) = arr.get_mut(i).and_then(|v| v.as_object_mut()) {
                        param_obj.insert("value".to_string(), Value::String(arg.clone()));
                    }
                }
            }

            if !node.children.is_empty() {
                let children_json = nodes_to_json(&node.children);
                node_json
                    .as_object_mut()
                    .unwrap()
                    .insert("children".to_string(), children_json);
            }

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

fn process_block_command(
    cmd: Arc<Command>,
    key: &String,
    value: &Value,
    parent_ctx: &mut ConfigContext,
) -> Result<(), ConfigError> {
    if cmd.unique {
        match value {
            Value::Object(obj) => {
                let args = extract_args(obj);
                let mut child_ctx = ConfigContext::new_empty(key, args);
                cmd.handle(&mut child_ctx, value);
                if let Some(children) = obj.get("children") {
                    process_final_config(children, &mut child_ctx)?;
                }
                parent_ctx.children.push(child_ctx);
            }
            Value::Array(arr) => {
                if arr.len() != 1 {
                    return Err(ConfigError::ValidationError(format!(
                        "Unique command {} must have exactly one instance",
                        key
                    )));
                }
                if let Some(Value::Object(obj)) = arr.first() {
                    let args = extract_args(obj);
                    let mut child_ctx = ConfigContext::new_empty(key, args);
                    cmd.handle(&mut child_ctx, arr.first().unwrap());
                    if let Some(children) = obj.get("children") {
                        process_final_config(children, &mut child_ctx)?;
                    }
                    parent_ctx.children.push(child_ctx);
                }
            }
            _ => {
                return Err(ConfigError::ValidationError(format!(
                    "Invalid format for unique command: {}",
                    key
                )));
            }
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
    Ok(())
}

fn process_non_block_command(
    cmd: Arc<Command>,
    key: &String,
    value: &Value,
    parent_ctx: &mut ConfigContext,
) -> Result<(), ConfigError> {
    match value {
        Value::Object(obj) => {
            let args = extract_args(obj);
            if args.iter().all(|arg| arg.is_empty()) {
                return Ok(()); // Skip commands with no arguments
            }
            parent_ctx.current_cmd_name = key.clone();
            parent_ctx.current_cmd_args = args;
            cmd.handle(parent_ctx, value);
            if let Some(children) = obj.get("children") {
                process_final_config(children, parent_ctx)?;
            }
        }
        Value::Array(arr) => {
            if arr.len() != 1 {
                return Err(ConfigError::ValidationError(format!(
                    "Non-unique command {} must be in an array with one element",
                    key
                )));
            }
            if let Some(Value::Object(obj)) = arr.first() {
                let args = extract_args(obj);
                if args.iter().all(|arg| arg.is_empty()) {
                    return Ok(()); // Skip commands with no arguments
                }
                parent_ctx.current_cmd_name = key.clone();
                parent_ctx.current_cmd_args = args;
                cmd.handle(parent_ctx, arr.first().unwrap());
                if let Some(children) = obj.get("children") {
                    process_final_config(children, parent_ctx)?;
                }
            }
        }
        _ => {
            return Err(ConfigError::ValidationError(format!(
                "Invalid format for non-block command: {}",
                key
            )));
        }
    }
    Ok(())
}

fn process_final_config(config: &Value, parent_ctx: &mut ConfigContext) -> Result<(), ConfigError> {
    if let Value::Object(map) = config {
        for (key, value) in map {
            if let Some(cmd) = get_command(key) {
                if cmd.is_block {
                    process_block_command(cmd, key, value, parent_ctx)?;
                } else {
                    process_non_block_command(cmd, key, value, parent_ctx)?;
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

pub fn load_config(
    storage_path: &str,
    config_file: Option<&str>,
    top_blocks: Vec<String>,
) -> Result<ConfigContext, ConfigError> {
    let complete_template =
        ConfigManager::get_complete_template(top_blocks).map_err(ConfigError::ValidationError)?;

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

    let user_config = if let Some(fc) = file_config {
        fc
    } else if let Some(sc) = stored_config {
        sc
    } else {
        json!({})
    };

    let final_config = merge_config(&complete_template, &user_config);

    fs::write(storage_path, serde_json::to_string_pretty(&final_config)?)?;

    let mut root_ctx = ConfigContext::new_empty("root", vec![]);
    process_final_config(&final_config, &mut root_ctx)?;

    Ok(root_ctx)
}
