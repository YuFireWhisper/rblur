use crate::core::config::config_manager::ConfigManager;
use crate::http::http_request::HttpRequest;
use crate::http::http_response::HttpResponse;
use http::{Method, StatusCode};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use thiserror::Error;

/// 定義 WebConfig 操作中可能發生的錯誤類型，包含 IO、JSON 解析與驗證錯誤。
#[derive(Error, Debug)]
pub enum WebConfigError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// WebConfig 結構提供對 JSON 配置檔案的讀取與修改功能。
/// 每次操作皆從檔案讀取最新內容，以防止外部修改導致資料不一致。
pub struct WebConfig {
    /// 配置檔案的路徑
    path: PathBuf,
    /// 用來同步檔案存取的 mutex
    file_lock: Mutex<()>,
}

impl WebConfig {
    /// 建構一個新的 WebConfig 實例。
    ///
    /// # 參數
    /// - `path`: 配置檔案的路徑。
    ///
    /// # 回傳
    /// - 成功: `Ok(WebConfig)` 實例。
    /// - 失敗: `Err(WebConfigError)`，例如檔案不存在或 JSON 解析失敗。
    pub fn new(path: &PathBuf) -> Result<Self, WebConfigError> {
        if !path.exists() {
            return Err(WebConfigError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Config file {} does not exist", path.display()),
            )));
        }
        // 讀取檔案並解析 JSON，以確保檔案內容合法
        let content = fs::read(path)?;
        let _: Value = serde_json::from_slice(&content)?;
        Ok(Self {
            path: path.clone(),
            file_lock: Mutex::new(()),
        })
    }

    /// 讀取並返回配置檔案中的 JSON 數據。
    ///
    /// # 回傳
    /// - 成功: `Ok(Value)`，包含完整的 JSON 配置內容。
    /// - 失敗: `Err(WebConfigError)`，包含錯誤詳細資訊。
    pub fn get_json(&self) -> Result<Value, WebConfigError> {
        let _guard = self.file_lock.lock().unwrap();
        let content = fs::read(&self.path)?;
        let json: Value = serde_json::from_slice(&content)?;
        Ok(json)
    }

    /// 更新配置檔中指定參數的值。
    ///
    /// 請求主體中的 JSON 必須包含：
    /// - `path`: 使用 JSON Pointer 的字串路徑，必須以 "/value" 結尾（例如 "/http/children/server/value"）。
    /// - `new_value`: 新的值（字串格式）。
    ///
    /// # 回傳
    /// - 成功: `Ok(())`。
    /// - 失敗: `Err(WebConfigError)`，例如路徑錯誤或型態驗證失敗。
    pub fn update_parameter(
        &self,
        json_pointer: &str,
        new_value: &str,
    ) -> Result<(), WebConfigError> {
        let _guard = self.file_lock.lock().unwrap();
        let content = fs::read(&self.path)?;
        let mut config: Value = serde_json::from_slice(&content)?;

        // 檢查 JSON Pointer 格式，必須以 '/' 開頭且以 "/value" 結尾
        if !json_pointer.starts_with('/') {
            return Err(WebConfigError::ValidationError(
                "JSON Pointer must start with '/'".into(),
            ));
        }
        if !json_pointer.ends_with("/value") {
            return Err(WebConfigError::ValidationError(
                "JSON Pointer must end with '/value'".into(),
            ));
        }

        // 取得父節點的 JSON Pointer，將最後的 "/value" 移除
        let parent_pointer = &json_pointer[..json_pointer.rfind('/').unwrap()];
        let parent = config.pointer_mut(parent_pointer).ok_or_else(|| {
            WebConfigError::ValidationError(format!("Invalid JSON pointer: {}", parent_pointer))
        })?;

        // 根據父節點的 "type" 欄位驗證並轉換新值
        let expected_type = parent.get("type").and_then(|v| v.as_str()).ok_or_else(|| {
            WebConfigError::ValidationError("Parameter missing 'type' field".into())
        })?;
        let default_val = parent.get("default").and_then(|v| v.as_str()).unwrap_or("");
        let validated_value = validate_and_convert(expected_type, new_value, default_val)?;
        parent
            .as_object_mut()
            .ok_or_else(|| WebConfigError::ValidationError("Parameter is not an object".into()))?
            .insert("value".into(), Value::String(validated_value));

        // 將更新後的配置寫回檔案
        let updated = serde_json::to_vec_pretty(&config)?;
        fs::write(&self.path, updated)?;
        println!("Updated config");
        Ok(())
    }

    /// 新增一個區塊到配置檔案中。
    ///
    /// 請求主體中的 JSON 必須包含：
    /// - `parent_path`: 父塊的 JSON Pointer 路徑（例如 "/" 或 "/http/children/server"）。
    /// - `block_name`: 要新增的區塊名稱。
    ///
    /// 流程：
    /// 1. 從父塊中尋找或建立 "children" 區塊。
    /// 2. 呼叫 `ConfigManager::get_block_template(block_name, true)` 取得完整區塊模板。
    /// 3. 檢查模板中的 unique 屬性，若為 true 則禁止新增。
    /// 4. 將新區塊加入對應子塊陣列中。
    ///
    /// # 回傳
    /// - 成功: `Ok(())`。
    /// - 失敗: `Err(WebConfigError)`，例如路徑錯誤或區塊為唯一區塊。
    pub fn add_block(&self, parent_path: &str, block_name: &str) -> Result<(), WebConfigError> {
        let _guard = self.file_lock.lock().unwrap();
        let content = fs::read(&self.path)?;
        let mut config: Value = serde_json::from_slice(&content)?;

        // 若 parent_path 為空則使用根節點，否則使用 JSON Pointer 存取父塊
        let parent = if parent_path.is_empty() {
            &mut config
        } else {
            config.pointer_mut(parent_path).ok_or_else(|| {
                WebConfigError::ValidationError(format!(
                    "Invalid parent JSON pointer: {}",
                    parent_path
                ))
            })?
        };
        let parent_obj = parent
            .as_object_mut()
            .ok_or_else(|| WebConfigError::ValidationError("Parent is not an object".into()))?;

        // 使用完整模板（包含所有子塊）
        let template = ConfigManager::get_block_template(block_name, true).ok_or_else(|| {
            WebConfigError::ValidationError(format!("Block {} not registered", block_name))
        })?;
        if template
            .get("unique")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Err(WebConfigError::ValidationError(format!(
                "Block {} is unique and cannot be added",
                block_name
            )));
        }

        // 取得或建立父塊中的 "children" 區塊
        let children_entry = if let Some(children_val) = parent_obj.get_mut("children") {
            if let Some(children_obj) = children_val.as_object_mut() {
                children_obj
            } else {
                return Err(WebConfigError::ValidationError(
                    "Parent's 'children' field is not an object".into(),
                ));
            }
        } else {
            parent_obj.insert(
                "children".to_string(),
                Value::Object(serde_json::Map::new()),
            );
            parent_obj
                .get_mut("children")
                .unwrap()
                .as_object_mut()
                .unwrap()
        };

        // 將新區塊新增到對應區塊的子陣列中
        if let Some(existing) = children_entry.get_mut(block_name) {
            if let Value::Array(arr) = existing {
                arr.push(template);
            } else {
                return Err(WebConfigError::ValidationError(format!(
                    "The 'children' field for {} is not an array",
                    block_name
                )));
            }
        } else {
            children_entry.insert(block_name.to_string(), Value::Array(vec![template]));
        }

        // 將更新後的配置寫回檔案
        let updated = serde_json::to_vec_pretty(&config)?;
        fs::write(&self.path, updated)?;
        Ok(())
    }

    /// 刪除配置檔中指定的區塊。
    ///
    /// 請求主體中的 JSON 必須包含：
    /// - `block_path`: 要刪除區塊的 JSON Pointer 路徑（例如 "/http/children/server" 或 "/http/children/server/1"）。
    ///
    /// 流程：
    /// 1. 根據 JSON Pointer 路徑尋找目標區塊的父節點及最後的 key 或 index。
    /// 2. 檢查該區塊是否為唯一區塊，若是則禁止刪除。
    /// 3. 若目標區塊為 array（非唯一的區塊）：
    ///    - 若陣列中多於一個值，則刪除指定索引或最後一個元素；
    ///    - 只有在陣列僅剩一個值時，才使用模板重置區塊。
    ///
    /// # 回傳
    /// - 成功: `Ok(())`。
    /// - 失敗: `Err(WebConfigError)`，例如路徑錯誤或區塊為唯一區塊。
    pub fn delete_block(&self, block_path: &str) -> Result<(), WebConfigError> {
        let _guard = self.file_lock.lock().unwrap();
        let content = fs::read(&self.path)?;
        let mut config: Value = serde_json::from_slice(&content)?;

        // 檢查 block_path 是否為合法的 JSON Pointer（必須以 '/' 開頭）
        if !block_path.starts_with('/') {
            return Err(WebConfigError::ValidationError(
                "Block path must start with '/'".into(),
            ));
        }

        // 將 block_path 分為父節點的 JSON Pointer 與最後一個 token
        let last_slash = block_path
            .rfind('/')
            .ok_or_else(|| WebConfigError::ValidationError("Invalid block path".into()))?;
        let parent_pointer = if last_slash == 0 {
            "" // 空字串代表根節點
        } else {
            &block_path[..last_slash]
        };
        let token = &block_path[last_slash + 1..];
        if token.is_empty() {
            return Err(WebConfigError::ValidationError(
                "Empty token in block path".into(),
            ));
        }

        // 取得父節點
        let parent = config.pointer_mut(parent_pointer).ok_or_else(|| {
            WebConfigError::ValidationError(format!(
                "Invalid JSON pointer for parent: {}",
                parent_pointer
            ))
        })?;

        // 若父節點為陣列，則 token 應為數字索引
        if let Some(arr) = parent.as_array_mut() {
            let index: usize = token.parse().map_err(|_| {
                WebConfigError::ValidationError(format!("Invalid array index: {}", token))
            })?;
            if index >= arr.len() {
                return Err(WebConfigError::ValidationError(format!(
                    "Index {} out of bounds",
                    index
                )));
            }
            // 從父節點的 JSON Pointer 取得區塊名稱（取最後一個 token）
            let block_name = if parent_pointer.is_empty() {
                token
            } else {
                parent_pointer.rsplit('/').next().unwrap_or(token)
            };
            let template =
                ConfigManager::get_block_template(block_name, true).ok_or_else(|| {
                    WebConfigError::ValidationError(format!("Block {} not registered", block_name))
                })?;
            if template
                .get("unique")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                return Err(WebConfigError::ValidationError(format!(
                    "Unique block {} cannot be deleted",
                    block_name
                )));
            }
            if arr.len() == 1 {
                *arr = vec![template];
            } else {
                arr.remove(index);
            }
        } else if let Some(obj) = parent.as_object_mut() {
            // 若父節點為物件，則 token 為物件的 key
            let block_value = obj.get_mut(token).ok_or_else(|| {
                WebConfigError::ValidationError(format!("Block {} not found", token))
            })?;
            let template = ConfigManager::get_block_template(token, true).ok_or_else(|| {
                WebConfigError::ValidationError(format!("Block {} not registered", token))
            })?;
            if template
                .get("unique")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                return Err(WebConfigError::ValidationError(format!(
                    "Unique block {} cannot be deleted",
                    token
                )));
            }
            if let Value::Array(arr) = block_value {
                match arr.len() {
                    0 => {
                        return Err(WebConfigError::ValidationError(format!(
                            "Block {} array is empty",
                            token
                        )));
                    }
                    1 => {
                        *arr = vec![template];
                    }
                    _ => {
                        arr.pop();
                    }
                }
            } else {
                obj.insert(token.to_string(), Value::Array(vec![template]));
            }
        } else {
            return Err(WebConfigError::ValidationError(
                "Parent is neither an array nor an object".into(),
            ));
        }
        let updated = serde_json::to_vec_pretty(&config)?;
        fs::write(&self.path, updated)?;
        Ok(())
    }
}

/// 根據期望型別驗證並轉換新值。
///
/// # 參數
/// - `expected_type`: 預期型別（例如 "bool", "string", "u16", "i32" 等）。
/// - `new_value`: 使用者提供的新值（字串）。
/// - `default`: 當新值為空時使用的預設值。
///
/// # 回傳
/// - 成功: `Ok(String)`，包含轉換後的值。
/// - 失敗: `Err(WebConfigError)`，包含驗證失敗原因。
fn validate_and_convert(
    expected_type: &str,
    new_value: &str,
    default: &str,
) -> Result<String, WebConfigError> {
    let trimmed = new_value.trim();
    if expected_type.eq_ignore_ascii_case("bool") {
        let lower = trimmed.to_lowercase();
        if lower == "true" || lower == "false" {
            Ok(lower)
        } else {
            Err(WebConfigError::ValidationError(format!(
                "Invalid boolean value: {}",
                new_value
            )))
        }
    } else if expected_type.eq_ignore_ascii_case("string") {
        if trimmed.is_empty() {
            Ok(default.to_string())
        } else {
            Ok(trimmed.to_string())
        }
    } else if expected_type.eq_ignore_ascii_case("u16")
        || expected_type.eq_ignore_ascii_case("u32")
        || expected_type.eq_ignore_ascii_case("i32")
        || expected_type.eq_ignore_ascii_case("u64")
        || expected_type.eq_ignore_ascii_case("i64")
    {
        if trimmed.is_empty() {
            Ok(default.to_string())
        } else if trimmed.parse::<i64>().is_ok() {
            Ok(trimmed.to_string())
        } else {
            Err(WebConfigError::ValidationError(format!(
                "Invalid numeric value: {}",
                new_value
            )))
        }
    } else if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// 以下函式用於向 HTTP 處理器中註冊 WebConfig 相關 API，並將各 API 綁定至對應的路徑上。
///
/// 註冊的 API 包含：
///
/// 1. **GET `/web_config/json`**
///    - **請求方式**: GET
///    - **路徑**: `/web_config/json`
///    - **請求主體**: 無
///    - **回應**:
///      - 成功: HTTP 200，回傳完整配置的 JSON，Content-Type 為 `application/json`
///      - 失敗: HTTP 500，回傳錯誤詳細訊息，Content-Type 為 `text/plain`
///
/// 2. **POST `/web_config/update`**
///    - **請求方式**: POST
///    - **路徑**: `/web_config/update`
///    - **請求主體**: JSON 格式，必須包含 `path` 與 `new_value` 欄位
///    - **回應**:
///      - 成功: HTTP 200，回傳 "Parameter updated"，Content-Type 為 `text/plain`
///      - 失敗: HTTP 400，回傳錯誤詳細訊息，Content-Type 為 `text/plain`
///
/// 3. **POST `/web_config/add_block`**
///    - **請求方式**: POST
///    - **路徑**: `/web_config/add_block`
///    - **請求主體**: JSON 格式，必須包含 `parent_path` 與 `block_name` 欄位
///    - **回應**:
///      - 成功: HTTP 200，回傳 "Block added"，Content-Type 為 `text/plain`
///      - 失敗: HTTP 400，回傳錯誤詳細訊息，Content-Type 為 `text/plain`
///
/// 4. **POST `/web_config/delete_block`**
///    - **請求方式**: POST
///    - **路徑**: `/web_config/delete_block`
///    - **請求主體**: JSON 格式，必須包含 `block_path` 欄位
///    - **回應**:
///      - 成功: HTTP 200，回傳 "Block deleted"，Content-Type 為 `text/plain`
///      - 失敗: HTTP 400，回傳錯誤詳細訊息，Content-Type 為 `text/plain`
pub fn add_all_web_config_handlers(
    web_config: Arc<WebConfig>,
    mut proc_lock: MutexGuard<'_, crate::core::processor::HttpProcessor>,
) {
    // Handler for GET /web_config/json
    proc_lock.add_handler(
        "/web_config/json".to_string(),
        StatusCode::OK,
        &Method::GET,
        Box::new({
            let wc = Arc::clone(&web_config);
            move |req: &HttpRequest| match wc.get_json() {
                Ok(json) => {
                    let mut resp = HttpResponse::new();
                    resp.set_status_line(req.version().to_owned(), StatusCode::OK);
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(&serde_json::to_string_pretty(&json).unwrap_or_default());
                    resp
                }
                Err(e) => {
                    let mut resp = HttpResponse::new();
                    resp.set_status_line(
                        req.version().to_owned(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    );
                    resp.set_header("Content-Type", "text/plain");
                    resp.set_body(&format!("Error: {:?}", e));
                    resp
                }
            }
        }),
    );

    // Handler for POST /web_config/update
    proc_lock.add_handler(
        "/web_config/update".to_string(),
        StatusCode::OK,
        &Method::POST,
        Box::new({
            let wc = Arc::clone(&web_config);
            move |req: &HttpRequest| {
                let body = String::from_utf8(req.body().to_vec()).unwrap_or_default();
                let req_json: Value = match serde_json::from_str(&body) {
                    Ok(j) => j,
                    Err(e) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(req.version().to_owned(), StatusCode::BAD_REQUEST);
                        resp.set_header("Content-Type", "text/plain");
                        resp.set_body(&format!("Invalid JSON: {:?}", e));
                        return resp;
                    }
                };
                let path = req_json.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let new_value = req_json
                    .get("new_value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                match wc.update_parameter(path, new_value) {
                    Ok(_) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(req.version().to_owned(), StatusCode::OK);
                        resp.set_header("Content-Type", "text/plain");
                        resp.set_body("Parameter updated");
                        resp
                    }
                    Err(e) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(req.version().to_owned(), StatusCode::BAD_REQUEST);
                        resp.set_header("Content-Type", "text/plain");
                        resp.set_body(&format!("Error: {:?}", e));
                        resp
                    }
                }
            }
        }),
    );

    // Handler for POST /web_config/add_block
    proc_lock.add_handler(
        "/web_config/add_block".to_string(),
        StatusCode::OK,
        &Method::POST,
        Box::new({
            let wc = Arc::clone(&web_config);
            move |req: &HttpRequest| {
                let body = String::from_utf8(req.body().to_vec()).unwrap_or_default();
                let req_json: Value = match serde_json::from_str(&body) {
                    Ok(j) => j,
                    Err(e) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(req.version().to_owned(), StatusCode::BAD_REQUEST);
                        resp.set_header("Content-Type", "text/plain");
                        resp.set_body(&format!("Invalid JSON: {:?}", e));
                        return resp;
                    }
                };
                let parent_path = req_json
                    .get("parent_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let block_name = req_json
                    .get("block_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                match wc.add_block(parent_path, block_name) {
                    Ok(_) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(req.version().to_owned(), StatusCode::OK);
                        resp.set_header("Content-Type", "text/plain");
                        resp.set_body("Block added");
                        resp
                    }
                    Err(e) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(req.version().to_owned(), StatusCode::BAD_REQUEST);
                        resp.set_header("Content-Type", "text/plain");
                        resp.set_body(&format!("Error: {:?}", e));
                        resp
                    }
                }
            }
        }),
    );

    // Handler for POST /web_config/delete_block
    proc_lock.add_handler(
        "/web_config/delete_block".to_string(),
        StatusCode::OK,
        &Method::POST,
        Box::new({
            let wc = Arc::clone(&web_config);
            move |req: &HttpRequest| {
                let body = String::from_utf8(req.body().to_vec()).unwrap_or_default();
                let req_json: Value = match serde_json::from_str(&body) {
                    Ok(j) => j,
                    Err(e) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(req.version().to_owned(), StatusCode::BAD_REQUEST);
                        resp.set_header("Content-Type", "text/plain");
                        resp.set_body(&format!("Invalid JSON: {:?}", e));
                        return resp;
                    }
                };
                let block_path = req_json
                    .get("block_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                match wc.delete_block(block_path) {
                    Ok(_) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(req.version().to_owned(), StatusCode::OK);
                        resp.set_header("Content-Type", "text/plain");
                        resp.set_body("Block deleted");
                        resp
                    }
                    Err(e) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(req.version().to_owned(), StatusCode::BAD_REQUEST);
                        resp.set_header("Content-Type", "text/plain");
                        resp.set_body(&format!("Error: {:?}", e));
                        resp
                    }
                }
            }
        }),
    );
}
