// config_loader.rs

use std::{collections::HashMap, fs, io};

use crate::core::config::command::handle_command;
use crate::core::config::config_context::ConfigContext;
use crate::core::config::storage::Storage;

/// 從配置檔載入並解析後存入 Storage 中
pub fn load_config_file<S: Storage>(file_path: &str, storage: &S) -> io::Result<()> {
    let content = fs::read_to_string(file_path)?;
    let nodes = parse_config(&content)?;
    store_tree(storage, "/config", &nodes)
}

/// 從 Storage 還原 ConfigContext 樹狀結構  
/// 根據儲存系統的目錄結構構建配置上下文，並呼叫各指令的處理函數
pub fn process_existing_config<S: Storage>(storage: &S) -> io::Result<ConfigContext> {
    let mut root_ctx = ConfigContext::new_empty("root".to_string(), vec![]);
    process_storage_config(storage, "/config", &mut root_ctx)?;
    Ok(root_ctx)
}

/// 遞迴讀取 Storage 中的配置，依照目錄結構建立 ConfigContext 樹  
/// 與原來不同的是：若目錄中除了 args/ 外還有其他子目錄，則當作一個塊，建立新的 ConfigContext；否則直接將指令作用於當前 ConfigContext
pub fn process_storage_config<S: Storage>(
    storage: &S,
    base_dir: &str,
    parent_ctx: &mut ConfigContext,
) -> io::Result<()> {
    let dirs = storage
        .list_dirs(base_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    // 過濾掉 Args 目錄，排序以保證順序一致
    let mut dirs: Vec<String> = dirs.into_iter().filter(|d| d != "Args").collect();
    dirs.sort();
    for dir in dirs {
        // 指令目錄格式為 "<command>_<id>"，只處理符合格式的目錄
        let parts: Vec<&str> = dir.rsplitn(2, '_').collect();
        if parts.len() != 2 {
            continue;
        }
        let cmd_name = parts[1].to_string();
        let cmd_dir = format!("{}/{}", base_dir, dir);
        // 讀取 args 子目錄
        let args_dir = format!("{}/Args", cmd_dir);
        let arg_dirs = storage.list_dirs(&args_dir).unwrap_or_default();
        let mut args_map: HashMap<usize, String> = HashMap::new();
        for arg_dir in arg_dirs {
            if let Ok(index) = arg_dir.parse::<usize>() {
                let value_file = format!("{}/{}/value", args_dir, arg_dir);
                if let Ok(content) = storage.read_file(&value_file) {
                    if let Ok(arg_value) = String::from_utf8(content) {
                        args_map.insert(index, arg_value);
                    }
                }
            }
        }
        let mut args = Vec::new();
        let mut i = 0;
        while let Some(val) = args_map.remove(&i) {
            args.push(val);
            i += 1;
        }
        // 檢查此目錄中是否還有除 Args 外的其他子目錄：有則為「塊」
        let sub_dirs = storage.list_dirs(&cmd_dir).unwrap_or_default();
        let is_block = sub_dirs.into_iter().any(|d| d != "Args");
        if is_block {
            // 塊：建立一個新的 ConfigContext，並呼叫 handle_command 進行初始化，再遞迴處理子目錄
            let mut child_ctx = ConfigContext::new_empty(cmd_name.clone(), args);
            handle_command(&mut child_ctx, true);
            process_storage_config(storage, &cmd_dir, &mut child_ctx)?;
            parent_ctx.children.push(child_ctx);
        } else {
            parent_ctx.current_cmd_name = cmd_name;
            parent_ctx.current_cmd_args = args;
            handle_command(parent_ctx, false);
        }
    }
    Ok(())
}

/// Token 定義，用來協助解析
#[derive(Debug)]
enum Token {
    Word(String),
    LBrace,    // {
    RBrace,    // }
    Semicolon, // ;
}

/// 取得下一個 token，會自動略過空白與註解（以 '#' 開頭直到行尾）
fn next_token(input: &str, pos: &mut usize) -> Option<Token> {
    let bytes = input.as_bytes();
    let len = bytes.len();

    // 跳過空白
    while *pos < len && bytes[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
    if *pos >= len {
        return None;
    }
    // 跳過註解
    if bytes[*pos] == b'#' {
        while *pos < len && bytes[*pos] != b'\n' {
            *pos += 1;
        }
        return next_token(input, pos);
    }
    match bytes[*pos] {
        b'{' => {
            *pos += 1;
            Some(Token::LBrace)
        }
        b'}' => {
            *pos += 1;
            Some(Token::RBrace)
        }
        b';' => {
            *pos += 1;
            Some(Token::Semicolon)
        }
        _ => {
            let start = *pos;
            while *pos < len {
                let c = bytes[*pos];
                if c.is_ascii_whitespace() || c == b'{' || c == b'}' || c == b';' || c == b'#' {
                    break;
                }
                *pos += 1;
            }
            Some(Token::Word(input[start..*pos].to_string()))
        }
    }
}

/// 從原始配置字串解析出樹狀結構
pub fn parse_config(input: &str) -> io::Result<Vec<ConfigNode>> {
    let mut pos = 0;
    Ok(parse_commands(input, &mut pos))
}

fn parse_commands(input: &str, pos: &mut usize) -> Vec<ConfigNode> {
    let mut nodes = Vec::new();
    while let Some(token) = next_token(input, pos) {
        match token {
            Token::RBrace => break, // 結束當前區塊
            Token::Word(cmd_name) => {
                let mut args = Vec::new();
                let mut children = Vec::new();
                loop {
                    match next_token(input, pos) {
                        Some(Token::Word(arg)) => args.push(arg),
                        Some(Token::Semicolon) => break,
                        Some(Token::LBrace) => {
                            children = parse_commands(input, pos);
                            break;
                        }
                        Some(Token::RBrace) => break, // 遇到右大括號直接結束，不回退 pos
                        None => break,
                    }
                }

                nodes.push(ConfigNode {
                    command: cmd_name,
                    args,
                    children,
                });
            }
            Token::LBrace => {
                let sub_nodes = parse_commands(input, pos);
                nodes.extend(sub_nodes);
            }
            Token::Semicolon => {} // 忽略孤立的分號
        }
    }
    nodes
}

/// 結構用來傳遞解析後的配置樹狀資訊
#[derive(Debug)]
pub struct ConfigNode {
    pub command: String,
    pub args: Vec<String>,
    pub children: Vec<ConfigNode>,
}

/// 將解析出的樹狀結構存入 Storage 中  
/// 結構規則：
/// - 在 base_dir 下建立每個指令的目錄：`<command>_<id>`
/// - 在每個目錄下建立 `Args` 子目錄，並在 `Args/<index>/value` 存入參數  
/// - 若指令有子指令則在同一目錄下繼續存放
pub fn store_tree<S: Storage>(
    storage: &S,
    base_dir: &str,
    nodes: &Vec<ConfigNode>,
) -> io::Result<()> {
    storage
        .create_dir_all(base_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    for node in nodes {
        // 根據同名目錄數量產生新的 id
        let pattern = format!("{}/{}_*", base_dir, node.command);
        let files = storage.read_files(&pattern).unwrap_or_default();
        let new_id = files.len();
        let cmd_dir = format!("{}/{}_{}", base_dir, node.command, new_id);
        storage
            .create_dir_all(&cmd_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        // 建立 Args 子目錄
        let args_dir = format!("{}/Args", cmd_dir);
        storage
            .create_dir_all(&args_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        // 寫入每個參數
        for (i, arg) in node.args.iter().enumerate() {
            let arg_dir = format!("{}/{}", args_dir, i);
            storage
                .create_dir_all(&arg_dir)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let value_file = format!("{}/value", arg_dir);
            storage
                .write_file(&value_file, arg.as_bytes())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }
        // 遞迴處理子節點（若有子指令就建立對應子目錄）
        store_tree(storage, &cmd_dir, &node.children)?;
    }
    Ok(())
}

