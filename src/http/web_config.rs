use std::{
    mem,
    path::PathBuf,
    sync::{Arc, MutexGuard},
};

use http::{Method, StatusCode};
use serde_json::Value;

use crate::core::{
    config::storage::{FileStorage, Storage},
    processor::HttpProcessor,
};

use super::{http_request::HttpRequest, http_response::HttpResponse};

pub struct WebConfig {
    storage: FileStorage,
}

const WEB_CONFIG_BASE_PATH: &str = "/blur-config";
const WEB_CONFIG_GET_PATH_PARAM: &str = "path";

impl WebConfig {
    pub fn new(storage_path: &PathBuf) -> Self {
        let storage = FileStorage::open(storage_path).unwrap();
        Self { storage }
    }

    /// 讀取檔案內容
    ///
    /// 請求方法: GET
    /// 請求路徑: /file
    /// 請求參數: path=路徑1&path=路徑2&...
    ///
    /// 回傳狀態碼: 200(成功)
    /// 回傳Body格式: 路徑: 內容(JSON)
    pub fn handle_get_file(&self, request: &HttpRequest) -> HttpResponse {
        let params = request.query_params();

        if let Some(paths) = params.get(WEB_CONFIG_GET_PATH_PARAM) {
            // 使用 Json 格式回傳
            // 路徑: 內容
            let mut resp = HttpResponse::new();
            let mut body = String::new();
            for path in paths {
                if let Ok(content) = self.storage.read_file(path) {
                    if let Ok(string_content) = String::from_utf8(content) {
                        body.push_str(&format!("{}: {}\n", path, string_content));
                    }
                }
            }

            resp.set_status_line(request.version().to_owned(), StatusCode::OK);
            resp.set_header("Content-Type", "application/json");
            resp.set_body(&body);
            return resp;
        }

        HttpProcessor::create_404_response(request.version())
    }

    /// 寫入檔案內容
    ///
    /// 請求方法: POST
    /// 請求路徑: /file
    /// 請求Body格式: 路徑: 內容(JSON)
    ///
    /// 回傳狀態碼: 200(成功)
    pub fn handle_post_file(&self, request: &HttpRequest) -> HttpResponse {
        let body = match String::from_utf8(request.body().to_vec()) {
            Ok(b) => b,
            Err(_) => {
                return mem::take(
                    HttpResponse::new()
                        .set_status_line(request.version().to_owned(), StatusCode::BAD_REQUEST),
                )
            }
        };

        for line in body.lines() {
            let mut parts = line.splitn(2, ':');
            let path = parts.next().map(str::trim);
            let content = parts.next().map(str::trim);

            if let (Some(path), Some(content)) = (path, content) {
                let parsed_content: Value = match serde_json::from_str(content) {
                    Ok(json) => json,
                    Err(_) => {
                        let mut resp = HttpResponse::new();
                        resp.set_status_line(request.version().to_owned(), StatusCode::BAD_REQUEST);
                        resp.set_body("Invalid JSON format");

                        return resp;
                    }
                };

                if let Err(e) = self
                    .storage
                    .write_file(path, parsed_content.to_string().as_bytes())
                {
                    let mut resp = HttpResponse::new();
                    resp.set_status_line(
                        request.version().to_owned(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    );
                    resp.set_body(&format!("Error: {}", e));

                    return resp;
                }
            }
        }

        let mut resp = HttpResponse::new();
        resp.set_status_line(request.version().to_owned(), StatusCode::OK);
        resp
    }

    /// 刪除檔案或目錄
    ///
    /// 請求方法: DELETE
    /// 請求路徑: /file
    /// 請求參數: path=路徑1&path=路徑2&...
    ///
    /// 回傳狀態碼: 200(成功)
    pub fn handle_delete_file(&self, request: &HttpRequest) -> HttpResponse {
        let params = request.query_params();

        if let Some(paths) = params.get(WEB_CONFIG_GET_PATH_PARAM) {
            for path in paths {
                if let Err(e) = self.storage.remove(path) {
                    let mut resp = HttpResponse::new();
                    resp.set_status_line(
                        request.version().to_owned(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    );
                    resp.set_body(&format!("Error: {}", e));
                    return mem::take(&mut resp);
                }
            }

            let mut resp = HttpResponse::new();
            resp.set_status_line(request.version().to_owned(), StatusCode::OK);
            return resp;
        }

        HttpProcessor::create_404_response(request.version())
    }

    /// 獲取指定目錄下的所有檔案名稱
    ///
    /// 請求方法: get
    /// 請求路徑: /list_files
    ///
    /// 回傳狀態碼: 200(成功)
    /// 回傳Body格式: 檔案名稱列表(JSON)
    pub fn handle_get_list_files(&self, request: &HttpRequest) -> HttpResponse {
        let params = request.query_params();

        if let Some(paths) = params.get(WEB_CONFIG_GET_PATH_PARAM) {
            let mut resp = HttpResponse::new();
            let mut body = String::new();
            for path in paths {
                if let Ok(files) = self.storage.list_files(path) {
                    body.push_str(&format!("{:?}\n", files));
                }
            }

            resp.set_status_line(request.version().to_owned(), StatusCode::OK);
            resp.set_header("Content-Type", "application/json");
            resp.set_body(&body);
            return resp;
        }

        HttpProcessor::create_404_response(request.version())
    }

    /// 獲取指定目錄下的所有目錄名稱
    ///
    /// 請求方法: get
    /// 請求路徑: /list_dirs
    ///
    /// 回傳狀態碼: 200(成功)
    /// 回傳Body格式: 目錄名稱列表(JSON)
    pub fn handle_get_list_dirs(&self, request: &HttpRequest) -> HttpResponse {
        let params = request.query_params();

        if let Some(paths) = params.get(WEB_CONFIG_GET_PATH_PARAM) {
            let mut resp = HttpResponse::new();
            let mut body = String::new();
            for path in paths {
                if let Ok(dirs) = self.storage.list_dirs(path) {
                    body.push_str(&format!("{:?}\n", dirs));
                }
            }

            resp.set_status_line(request.version().to_owned(), StatusCode::OK);
            resp.set_header("Content-Type", "application/json");
            resp.set_body(&body);
            return resp;
        }

        HttpProcessor::create_404_response(request.version())
    }

    /// 遍歷指定目錄下的所有檔案
    /// 回傳檔案路徑與檔案內容的對應表
    ///
    /// 請求方法: GET
    /// 請求路徑: /traverse
    /// 請求參數: path=目錄路徑
    ///
    /// 回傳狀態碼: 200(成功)
    /// 回傳Body格式: 路徑: 內容(JSON)
    pub fn handle_get_traverse(&self, request: &HttpRequest) -> HttpResponse {
        let params = request.query_params();

        if let Some(paths) = params.get(WEB_CONFIG_GET_PATH_PARAM) {
            let mut resp = HttpResponse::new();
            let mut body = String::new();
            for path in paths {
                if let Ok(files) = self.storage.traverse(path) {
                    for (file, content) in files {
                        body.push_str(&format!("{}: {:?}\n", file, String::from_utf8(content)));
                    }
                }
            }

            resp.set_status_line(request.version().to_owned(), StatusCode::OK);
            resp.set_header("Content-Type", "application/json");
            resp.set_body(&body);
            return resp;
        }

        HttpProcessor::create_404_response(request.version())
    }
}

pub fn add_all_web_config_handlers(
    web_config: Arc<WebConfig>,
    mut proc_lock: MutexGuard<'_, HttpProcessor>,
) {
    proc_lock.add_handler(
        format!("{}/file", WEB_CONFIG_BASE_PATH),
        StatusCode::OK,
        &Method::GET,
        Box::new({
            let web_config = Arc::clone(&web_config);
            move |req| web_config.handle_get_file(req)
        }),
    );

    proc_lock.add_handler(
        format!("{}/file", WEB_CONFIG_BASE_PATH),
        StatusCode::OK,
        &Method::POST,
        Box::new({
            let web_config = Arc::clone(&web_config);
            move |req| web_config.handle_post_file(req)
        }),
    );

    proc_lock.add_handler(
        format!("{}/file", WEB_CONFIG_BASE_PATH),
        StatusCode::OK,
        &Method::DELETE,
        Box::new({
            let web_config = Arc::clone(&web_config);
            move |req| web_config.handle_delete_file(req)
        }),
    );

    proc_lock.add_handler(
        format!("{}/list_files", WEB_CONFIG_BASE_PATH),
        StatusCode::OK,
        &Method::GET,
        Box::new({
            let web_config = Arc::clone(&web_config);
            move |req| web_config.handle_get_list_files(req)
        }),
    );

    proc_lock.add_handler(
        format!("{}/list_dirs", WEB_CONFIG_BASE_PATH),
        StatusCode::OK,
        &Method::GET,
        Box::new({
            let web_config = Arc::clone(&web_config);
            move |req| web_config.handle_get_list_dirs(req)
        }),
    );

    proc_lock.add_handler(
        format!("{}/traverse", WEB_CONFIG_BASE_PATH),
        StatusCode::OK,
        &Method::GET,
        Box::new({
            let web_config = Arc::clone(&web_config);
            move |req| web_config.handle_get_traverse(req)
        }),
    );

    proc_lock.add_handler(
        format!("{}/file", WEB_CONFIG_BASE_PATH),
        StatusCode::OK,
        &Method::POST,
        Box::new({
            let web_config = Arc::clone(&web_config);
            move |req| web_config.handle_post_file(req)
        }),
    );
}
