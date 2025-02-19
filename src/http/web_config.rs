use crate::core::config::config_manager::ConfigManager;
use crate::http::http_request::HttpRequest;
use crate::http::http_response::HttpResponse;
use http::{Method, StatusCode};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WebConfigError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Validation error: {0}")]
    ValidationError(String),
}

const FRONTEND_REPO_URL: &str = "https://github.com/YuFireWhisper/blur-web-config.git";

pub struct WebConfig {
    path: PathBuf,
    file_lock: Mutex<()>,
}

impl WebConfig {
    pub fn new(path: &PathBuf) -> Result<Self, WebConfigError> {
        if !path.exists() {
            return Err(WebConfigError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Config file {} does not exist", path.display()),
            )));
        }
        let content = fs::read(path)?;
        let _: Value = serde_json::from_slice(&content)?;
        ensure_static_up_to_date()?;
        Ok(Self {
            path: path.clone(),
            file_lock: Mutex::new(()),
        })
    }

    pub fn get_json(&self) -> Result<Value, WebConfigError> {
        let _guard = self.file_lock.lock().unwrap();
        let content = fs::read(&self.path)?;
        let json: Value = serde_json::from_slice(&content)?;
        Ok(json)
    }

    pub fn update_parameter(
        &self,
        json_pointer: &str,
        new_value: &str,
    ) -> Result<(), WebConfigError> {
        let _guard = self.file_lock.lock().unwrap();
        let content = fs::read(&self.path)?;
        let mut config: Value = serde_json::from_slice(&content)?;

        self.validate_json_pointer(json_pointer)?;

        let parent_pointer = &json_pointer[..json_pointer.rfind('/').unwrap()];
        let parent = config.pointer_mut(parent_pointer).ok_or_else(|| {
            WebConfigError::ValidationError(format!("Invalid JSON pointer: {}", parent_pointer))
        })?;

        self.update_json_value(parent, new_value)?;

        let updated = serde_json::to_vec_pretty(&config)?;
        fs::write(&self.path, updated)?;
        Ok(())
    }

    fn validate_json_pointer(&self, json_pointer: &str) -> Result<(), WebConfigError> {
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
        Ok(())
    }

    fn update_json_value(&self, parent: &mut Value, new_value: &str) -> Result<(), WebConfigError> {
        let expected_type = parent.get("type").and_then(|v| v.as_str()).ok_or_else(|| {
            WebConfigError::ValidationError("Parameter missing 'type' field".into())
        })?;
        let default_val = parent.get("default").and_then(|v| v.as_str()).unwrap_or("");
        let validated_value = validate_and_convert(expected_type, new_value, default_val)?;
        parent
            .as_object_mut()
            .ok_or_else(|| WebConfigError::ValidationError("Parameter is not an object".into()))?
            .insert("value".into(), Value::String(validated_value));
        Ok(())
    }

    pub fn add_block(&self, parent_path: &str, block_name: &str) -> Result<(), WebConfigError> {
        let _guard = self.file_lock.lock().unwrap();
        let content = fs::read(&self.path)?;
        let mut config: Value = serde_json::from_slice(&content)?;

        self.add_block_to_config(&mut config, parent_path, block_name)?;

        let updated = serde_json::to_vec_pretty(&config)?;
        fs::write(&self.path, updated)?;
        Ok(())
    }

    fn add_block_to_config(
        &self,
        config: &mut Value,
        parent_path: &str,
        block_name: &str,
    ) -> Result<(), WebConfigError> {
        let parent = self.get_parent_block_mut(config, parent_path)?;
        let parent_obj = self.get_parent_object_mut(parent)?;
        let template = self.get_block_template(block_name)?;

        self.validate_block_uniqueness(&template, block_name)?;

        let children_entry = self.ensure_children_object_exists(parent_obj)?;
        self.add_template_to_children(children_entry, block_name, template)?;

        Ok(())
    }

    fn get_parent_block_mut<'a>(
        &self,
        config: &'a mut Value,
        parent_path: &str,
    ) -> Result<&'a mut Value, WebConfigError> {
        if parent_path.is_empty() {
            Ok(config)
        } else {
            config.pointer_mut(parent_path).ok_or_else(|| {
                WebConfigError::ValidationError(format!(
                    "Invalid parent JSON pointer: {}",
                    parent_path
                ))
            })
        }
    }

    fn get_parent_object_mut<'a>(
        &self,
        parent: &'a mut Value,
    ) -> Result<&'a mut serde_json::Map<String, Value>, WebConfigError> {
        parent
            .as_object_mut()
            .ok_or_else(|| WebConfigError::ValidationError("Parent is not an object".into()))
    }

    fn get_block_template(&self, block_name: &str) -> Result<Value, WebConfigError> {
        ConfigManager::get_block_template(block_name, true).ok_or_else(|| {
            WebConfigError::ValidationError(format!("Block {} not registered", block_name))
        })
    }

    fn validate_block_uniqueness(
        &self,
        template: &Value,
        block_name: &str,
    ) -> Result<(), WebConfigError> {
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
        Ok(())
    }

    fn ensure_children_object_exists<'a>(
        &self,
        parent_obj: &'a mut serde_json::Map<String, Value>,
    ) -> Result<&'a mut serde_json::Map<String, Value>, WebConfigError> {
        if parent_obj.contains_key("children") {
            if let Some(children_val) = parent_obj.get_mut("children") {
                children_val.as_object_mut().ok_or_else(|| {
                    WebConfigError::ValidationError(
                        "Parent's 'children' field is not an object".into(),
                    )
                })
            } else {
                Err(WebConfigError::ValidationError(
                    "Unexpected error accessing 'children' field".into(),
                ))
            }
        } else {
            parent_obj.insert(
                "children".to_string(),
                Value::Object(serde_json::Map::new()),
            );
            parent_obj
                .get_mut("children")
                .and_then(|v| v.as_object_mut())
                .ok_or_else(|| {
                    WebConfigError::ValidationError(
                        "Failed to create or access 'children' object".into(),
                    )
                })
        }
    }

    fn add_template_to_children(
        &self,
        children_entry: &mut serde_json::Map<String, Value>,
        block_name: &str,
        template: Value,
    ) -> Result<(), WebConfigError> {
        if let Some(existing) = children_entry.get_mut(block_name) {
            if let Some(arr) = existing.as_array_mut() {
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
        Ok(())
    }

    pub fn delete_block(&self, block_path: &str) -> Result<(), WebConfigError> {
        let _guard = self.file_lock.lock().unwrap();
        let content = fs::read(&self.path)?;
        let mut config: Value = serde_json::from_slice(&content)?;

        self.delete_block_from_config(&mut config, block_path)?;

        let updated = serde_json::to_vec_pretty(&config)?;
        fs::write(&self.path, updated)?;
        Ok(())
    }

    fn delete_block_from_config(
        &self,
        config: &mut Value,
        block_path: &str,
    ) -> Result<(), WebConfigError> {
        if !block_path.starts_with('/') {
            return Err(WebConfigError::ValidationError(
                "Block path must start with '/'".into(),
            ));
        }

        let (parent_pointer, token) = self.parse_block_path(block_path)?;
        let parent = self.get_deletable_parent_mut(config, parent_pointer)?;

        self.process_block_deletion(parent, token, parent_pointer)?;
        Ok(())
    }

    fn parse_block_path<'a>(
        &self,
        block_path: &'a str,
    ) -> Result<(&'a str, &'a str), WebConfigError> {
        let last_slash = block_path
            .rfind('/')
            .ok_or_else(|| WebConfigError::ValidationError("Invalid block path".into()))?;
        let parent_pointer = if last_slash == 0 {
            ""
        } else {
            &block_path[..last_slash]
        };
        let token = &block_path[last_slash + 1..];
        if token.is_empty() {
            return Err(WebConfigError::ValidationError(
                "Empty token in block path".into(),
            ));
        }
        Ok((parent_pointer, token))
    }

    fn get_deletable_parent_mut<'a>(
        &self,
        config: &'a mut Value,
        parent_pointer: &str,
    ) -> Result<&'a mut Value, WebConfigError> {
        config.pointer_mut(parent_pointer).ok_or_else(|| {
            WebConfigError::ValidationError(format!(
                "Invalid JSON pointer for parent: {}",
                parent_pointer
            ))
        })
    }

    fn process_block_deletion(
        &self,
        parent: &mut Value,
        token: &str,
        parent_pointer: &str,
    ) -> Result<(), WebConfigError> {
        if let Some(arr) = parent.as_array_mut() {
            self.remove_block_from_array(arr, token, parent_pointer)?;
        } else if let Some(obj) = parent.as_object_mut() {
            self.remove_block_from_object(obj, token)?;
        } else {
            return Err(WebConfigError::ValidationError(
                "Parent is neither an array nor an object".into(),
            ));
        }
        Ok(())
    }

    fn remove_block_from_array(
        &self,
        arr: &mut Vec<Value>,
        token: &str,
        parent_pointer: &str,
    ) -> Result<(), WebConfigError> {
        let index: usize = token.parse().map_err(|_| {
            WebConfigError::ValidationError(format!("Invalid array index: {}", token))
        })?;
        if index >= arr.len() {
            return Err(WebConfigError::ValidationError(format!(
                "Index {} out of bounds",
                index
            )));
        }

        let block_name = if parent_pointer.is_empty() {
            token
        } else {
            parent_pointer.rsplit('/').next().unwrap_or(token)
        };
        let template = self.get_block_template(block_name)?;
        self.validate_block_uniqueness_deletion(&template, block_name)?;

        if arr.len() == 1 {
            *arr = vec![template];
        } else {
            arr.remove(index);
        }
        Ok(())
    }

    fn remove_block_from_object(
        &self,
        obj: &mut serde_json::Map<String, Value>,
        token: &str,
    ) -> Result<(), WebConfigError> {
        let block_value = obj
            .get_mut(token)
            .ok_or_else(|| WebConfigError::ValidationError(format!("Block {} not found", token)))?;
        let template = self.get_block_template(token)?;
        self.validate_block_uniqueness_deletion(&template, token)?;

        if let Value::Array(arr) = block_value {
            match arr.len() {
                0 => Err(WebConfigError::ValidationError(format!(
                    "Block {} array is empty",
                    token
                ))),
                1 => {
                    *arr = vec![template];
                    Ok(())
                }
                _ => {
                    arr.pop();
                    Ok(())
                }
            }
        } else {
            obj.insert(token.to_string(), Value::Array(vec![template]));
            Ok(())
        }
    }

    fn validate_block_uniqueness_deletion(
        &self,
        template: &Value,
        block_name: &str,
    ) -> Result<(), WebConfigError> {
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
        Ok(())
    }
}

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

pub fn add_all_web_config_handlers(
    web_config: Arc<WebConfig>,
    mut proc_lock: MutexGuard<'_, crate::core::processor::HttpProcessor>,
) {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let static_path = format!("{}/static/dist/", project_root);
    proc_lock
        .serve_static_at("/web_config", &static_path)
        .expect("Failed to register /web_config mapping");

    register_get_json_handler(&web_config, &mut proc_lock);
    register_update_handler(&web_config, &mut proc_lock);
    register_add_block_handler(&web_config, &mut proc_lock);
    register_delete_block_handler(&web_config, &mut proc_lock);

    proc_lock
        .serve_file_at(
            "/web_config/*",
            format!("{}/static/dist/index.html", project_root),
        )
        .expect("Failed to register /web_config/* mapping");
}

fn register_get_json_handler(
    web_config: &Arc<WebConfig>,
    proc_lock: &mut MutexGuard<'_, crate::core::processor::HttpProcessor>,
) {
    proc_lock.add_handler(
        "/web_config/json".to_string(),
        StatusCode::OK,
        &Method::GET,
        Box::new({
            let wc = Arc::clone(web_config);
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
}

fn register_update_handler(
    web_config: &Arc<WebConfig>,
    proc_lock: &mut MutexGuard<'_, crate::core::processor::HttpProcessor>,
) {
    proc_lock.add_handler(
        "/web_config/update".to_string(),
        StatusCode::OK,
        &Method::POST,
        Box::new({
            let wc = Arc::clone(web_config);
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
}

fn register_add_block_handler(
    web_config: &Arc<WebConfig>,
    proc_lock: &mut MutexGuard<'_, crate::core::processor::HttpProcessor>,
) {
    proc_lock.add_handler(
        "/web_config/add_block".to_string(),
        StatusCode::OK,
        &Method::POST,
        Box::new({
            let wc = Arc::clone(web_config);
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
}

fn register_delete_block_handler(
    web_config: &Arc<WebConfig>,
    proc_lock: &mut MutexGuard<'_, crate::core::processor::HttpProcessor>,
) {
    proc_lock.add_handler(
        "/web_config/delete_block".to_string(),
        StatusCode::OK,
        &Method::POST,
        Box::new({
            let wc = Arc::clone(web_config);
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

fn ensure_static_up_to_date() -> Result<PathBuf, WebConfigError> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_dir = PathBuf::from(manifest_dir).join("static");
    let dist_dir = repo_dir.join("dist");

    if needs_update(&repo_dir)? {
        if !repo_dir.exists() {
            let status = Command::new("git")
                .args(["clone", FRONTEND_REPO_URL, repo_dir.to_str().unwrap()])
                .status()
                .map_err(|e| {
                    WebConfigError::ValidationError(format!("Failed to clone repository: {}", e))
                })?;
            if !status.success() {
                return Err(WebConfigError::ValidationError("Git clone failed".into()));
            }
        } else {
            let status = Command::new("git")
                .args(["pull"])
                .current_dir(&repo_dir)
                .status()
                .map_err(|e| {
                    WebConfigError::ValidationError(format!("Failed to run git pull: {}", e))
                })?;

            if !status.success() {
                return Err(WebConfigError::ValidationError("Git pull failed".into()));
            }
        }

        let install_status = Command::new("npm")
            .arg("install")
            .current_dir(&repo_dir)
            .status()
            .map_err(|e| {
                WebConfigError::ValidationError(format!("Failed to run npm install: {}", e))
            })?;
        if !install_status.success() {
            return Err(WebConfigError::ValidationError("npm install failed".into()));
        }

        let build_status = Command::new("npm")
            .arg("run")
            .arg("build")
            .current_dir(&repo_dir)
            .status()
            .map_err(|e| {
                WebConfigError::ValidationError(format!("Failed to run npm run build: {}", e))
            })?;
        if !build_status.success() {
            return Err(WebConfigError::ValidationError(
                "npm run build failed".into(),
            ));
        }

        if !dist_dir.exists() {
            return Err(WebConfigError::ValidationError(
                "Build did not produce dist directory".into(),
            ));
        }
    }

    Ok(dist_dir)
}

fn needs_update(static_dir: &Path) -> Result<bool, WebConfigError> {
    if !static_dir.exists() || !static_dir.join(".git").exists() {
        println!("Static files or .git directory not found, need update");
        return Ok(true);
    }

    if !static_dir.join("dist/index.html").exists() {
        println!("dist/index.html not found, need update (likely initial clone)");
        return Ok(true);
    }

    println!("Static files found, checking git status");

    let branch_name = Command::new("git")
        .args(["branch", "--show-current"])
        .current_dir(static_dir)
        .output()
        .map_err(|e| {
            WebConfigError::ValidationError(format!("Failed to get current branch: {}", e))
        })?
        .stdout;
    let branch_name = String::from_utf8_lossy(&branch_name).trim().to_string();

    let fetch_status = Command::new("git")
        .args(["fetch", "origin"])
        .current_dir(static_dir)
        .status()
        .map_err(|e| WebConfigError::ValidationError(format!("Failed to fetch: {}", e)))?;

    if !fetch_status.success() {
        return Err(WebConfigError::ValidationError("Git fetch failed".into()));
    }

    let get_git_hash = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(static_dir)
            .output()
            .map(|output| {
                if output.status.success() {
                    String::from_utf8_lossy(&output.stdout).trim().to_string()
                } else {
                    String::new()
                }
            })
            .unwrap_or_default()
    };

    let head = get_git_hash(&["rev-parse", "HEAD"]);
    let upstream = if !branch_name.is_empty() {
        get_git_hash(&["rev-parse", &format!("origin/{}", branch_name)])
    } else {
        String::new()
    };

    if head.is_empty() || upstream.is_empty() {
        println!("Git commands failed (possibly detached HEAD or no upstream), forcing update.");
        return Ok(true);
    }

    Ok(head != upstream)
}
