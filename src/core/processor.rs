use crate::http::http_response::get_content_type;
use crate::http::{http_request::HttpRequest, http_response::HttpResponse};
use http::{Method, StatusCode, Version};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

type ProcessorResult<T> = Result<T, ProcessorError>;

#[derive(Debug, Error)]
pub enum ProcessorError {
    #[error("Parsing request failed")]
    ParseError,
    #[error("File operation failed: {0}")]
    FileError(String),
    #[error("File path can't be a directory")]
    NotAFile,
}

pub type ProcessorResponse = Vec<u8>;

pub trait Processor {
    fn process(&self, request: Vec<u8>) -> ProcessorResult<ProcessorResponse>;
}

pub type HttpHandler = Box<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static>;
pub type PathMapper = dyn Fn(&str) -> Option<String> + Send + Sync + 'static;

#[derive(Default)]
pub struct StaticFileConfig {
    prefix: Option<String>,
    file_path: PathBuf,
    path_mapper: Option<Arc<PathMapper>>,
    strip_prefix: Option<PathBuf>,
}

impl StaticFileConfig {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            prefix: None,
            file_path: path.as_ref().to_path_buf(),
            path_mapper: None,
            strip_prefix: None,
        }
    }

    pub fn with_prefix(mut self, prefix: impl AsRef<str>) -> Self {
        let mut p = prefix.as_ref().to_string();
        if p != "/" {
            p = p.trim_end_matches('/').to_string();
        }
        self.prefix = Some(p);
        self
    }

    pub fn with_mapper(
        mut self,
        mapper: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.path_mapper = Some(Arc::new(mapper));
        self
    }

    pub fn with_strip_prefix(mut self, prefix: impl AsRef<Path>) -> Self {
        self.strip_prefix = Some(prefix.as_ref().to_path_buf());
        self
    }
}

#[derive(Default)]
pub struct HttpProcessor {
    handlers: HashMap<(String, StatusCode, &'static Method), Arc<HttpHandler>>,
    excluded_files: Vec<PathBuf>,
}

impl HttpProcessor {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            excluded_files: Vec::new(),
        }
    }

    pub fn add_handler(
        &mut self,
        path: String,
        code: StatusCode,
        method: &'static Method,
        handler: HttpHandler,
    ) {
        let normalized_path = if path != "/" && path.ends_with('/') {
            path.trim_end_matches('/').to_string()
        } else {
            path
        };
        self.handlers
            .insert((normalized_path, code, method), Arc::new(handler));
    }

    pub fn serve_static(&mut self, path: impl AsRef<Path>) -> Result<(), ProcessorError> {
        let p = path.as_ref();
        let config = StaticFileConfig::new(p).with_strip_prefix(p);
        self.serve_static_with_config(config)
    }

    pub fn serve_static_at(
        &mut self,
        prefix: impl AsRef<str>,
        path: impl AsRef<Path>,
    ) -> Result<(), ProcessorError> {
        let p = path.as_ref();
        let config = StaticFileConfig::new(p)
            .with_prefix(prefix)
            .with_strip_prefix(p); // Keep strip_prefix for correct path calculation
        self.serve_static_with_config(config)
    }

    pub fn serve_file_at(
        &mut self,
        url_path: impl AsRef<str>,
        file_path: impl AsRef<Path>,
    ) -> Result<(), ProcessorError> {
        if file_path.as_ref().is_dir() {
            return Err(ProcessorError::NotAFile);
        }
        let config = StaticFileConfig::new(file_path).with_prefix(url_path);
        self.serve_static_file_with_config(&config.file_path, config.prefix.as_deref(), None)
    }

    pub fn serve_static_with_mapper(
        &mut self,
        path: impl AsRef<Path>,
        mapper: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<(), ProcessorError> {
        let config = StaticFileConfig::new(path).with_mapper(mapper);
        self.serve_static_with_config(config)
    }

    fn serve_static_with_config(&mut self, config: StaticFileConfig) -> Result<(), ProcessorError> {
        let path = config.file_path;
        if path.is_dir() {
            self.serve_static_directory_with_config(
                &path,
                config.prefix.as_deref(),
                config.strip_prefix.as_deref(),
                config.path_mapper,
            )?;
        } else {
            self.serve_static_file_with_config(
                &path,
                config.prefix.as_deref(),
                config.strip_prefix.as_deref(),
            )?;
        }
        Ok(())
    }

    pub fn exclude_file(&mut self, path: impl AsRef<Path>) {
        self.excluded_files.push(path.as_ref().to_path_buf());
    }

    fn read_file_content(file_path: &Path) -> Result<Arc<String>, ProcessorError> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| ProcessorError::FileError(e.to_string()))?;
        Ok(Arc::new(content))
    }

    fn compute_url_path(
        file_path: &Path,
        prefix: Option<&str>,
        strip_prefix: Option<&Path>,
    ) -> String {
        let mut url_path = String::new();

        if let Some(prefix) = prefix {
            url_path.push_str(prefix);
        }

        if let Some(strip_prefix) = strip_prefix {
            if let Ok(relative_path) = file_path.strip_prefix(strip_prefix) {
                let relative_path_str = relative_path.to_string_lossy().replace("\\", "/");
                if !url_path.ends_with('/') && !relative_path_str.is_empty() {
                    url_path.push('/');
                }
                url_path.push_str(&relative_path_str);
            }
        } else {
            let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
            if !url_path.ends_with('/') && !file_name.is_empty() {
                url_path.push('/');
            }
            url_path.push_str(&file_name);
        }

        if url_path.ends_with("index.html") {
            url_path = url_path.replace("index.html", "");
        }
        if url_path.is_empty() || !url_path.starts_with("/") {
            url_path.insert(0, '/');
        }

        url_path
    }

    fn register_static_handler(
        &mut self,
        url_path: &str,
        content: Arc<String>,
        content_type: String,
    ) {
        let handler = Box::new(move |req: &HttpRequest| {
            let mut resp = HttpResponse::new();
            resp.set_status_line(*req.version(), StatusCode::OK);
            resp.set_header("Content-Type", &content_type);
            resp.set_body(&content);
            resp
        });
        self.add_handler(url_path.to_string(), StatusCode::OK, &Method::GET, handler);
    }

    fn serve_static_file_with_config(
        &mut self,
        file_path: &Path,
        prefix: Option<&str>,
        strip_prefix: Option<&Path>,
    ) -> Result<(), ProcessorError> {
        if self.excluded_files.contains(&file_path.to_path_buf()) {
            return Ok(());
        }
        let content = Self::read_file_content(file_path)?;
        let content_type = get_content_type(&file_path.to_string_lossy()).to_string();
        let url_path = Self::compute_url_path(file_path, prefix, strip_prefix);
        self.register_static_handler(&url_path, content, content_type);
        Ok(())
    }

    fn serve_static_directory_with_config(
        &mut self,
        dir_path: &Path,
        prefix: Option<&str>,
        strip_prefix: Option<&Path>,
        mapper: Option<Arc<PathMapper>>,
    ) -> Result<(), ProcessorError> {
        if !dir_path.is_dir() {
            return Err(ProcessorError::FileError("Not a directory".to_string()));
        }

        for entry in
            std::fs::read_dir(dir_path).map_err(|e| ProcessorError::FileError(e.to_string()))?
        {
            let entry = entry.map_err(|e| ProcessorError::FileError(e.to_string()))?;
            let path = entry.path();

            if path.is_file() {
                self.serve_static_entry(&path, prefix, strip_prefix, mapper.clone())?;
            } else if path.is_dir() {
                self.serve_static_directory_with_config(
                    &path,
                    prefix,
                    strip_prefix,
                    mapper.clone(),
                )?;
            }
        }
        Ok(())
    }

    fn serve_static_entry(
        &mut self,
        path: &Path,
        prefix: Option<&str>,
        strip_prefix: Option<&Path>,
        mapper: Option<Arc<PathMapper>>,
    ) -> Result<(), ProcessorError> {
        if let Some(ref mapper) = mapper {
            if let Some(mapped_path) = mapper(&path.to_string_lossy()) {
                self.serve_file_at(mapped_path, path)?;
            } else {
                self.serve_static_file_with_config(path, prefix, strip_prefix)?;
            }
        } else {
            self.serve_static_file_with_config(path, prefix, strip_prefix)?;
        }
        Ok(())
    }

    fn find_handler<'a>(&'a self, path: &str, method: &'a Method) -> Option<&'a Arc<HttpHandler>> {
        if let Some(handler) = self
            .handlers
            .get(&(path.to_string(), StatusCode::OK, method))
        {
            return Some(handler);
        }

        let normalized_path = path.trim_end_matches('/');
        if normalized_path != path {
            if let Some(handler) =
                self.handlers
                    .get(&(normalized_path.to_string(), StatusCode::OK, method))
            {
                return Some(handler);
            }
        }

        let mut matched_handler = None;
        let mut longest_match = 0;

        for ((key, _, key_method), handler) in &self.handlers {
            if key_method != method {
                continue;
            }
            if key.contains("*") {
                continue;
            }
            if key == path {
                return Some(handler);
            }
        }

        for ((pattern, _, pattern_method), handler) in &self.handlers {
            if method != *pattern_method {
                continue;
            }

            if let Some(star_pos) = pattern.find('*') {
                let prefix = &pattern[..star_pos];
                let suffix = &pattern[star_pos + 1..];

                if path.starts_with(prefix) && path.ends_with(suffix) {
                    let match_length = prefix.len() + suffix.len();
                    if match_length > longest_match {
                        matched_handler = Some(handler);
                        longest_match = match_length;
                    }
                }
            }
        }

        matched_handler
    }

    pub fn create_404_response(http_version: &Version) -> HttpResponse {
        let mut response = HttpResponse::new();
        response.set_status_line(*http_version, StatusCode::NOT_FOUND);
        response.set_header("Content-Type", "text/plain");
        response.set_body("404 Not Found");
        response
    }

    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

impl Processor for HttpProcessor {
    fn process(&self, request: Vec<u8>) -> ProcessorResult<ProcessorResponse> {
        let mut req = HttpRequest::new();
        req.parse(&request)
            .map_err(|_| ProcessorError::ParseError)?;

        let clean_path = req.path().split('?').next().unwrap().to_owned();
        let method = req.method();

        if let Some(handler) = self.find_handler(&clean_path, method) {
            let response = handler(&req);
            return Ok(response.as_bytes());
        }

        if let Some(handler) = self.find_handler(&clean_path, &Method::OPTIONS) {
            let response = handler(&req);
            return Ok(response.as_bytes());
        }

        if *method == Method::OPTIONS {
            let mut response = HttpResponse::new();
            response.set_status_line(*req.version(), StatusCode::OK);
            response.set_header("Content-Type", "text/plain");
            response.set_body("");
            return Ok(response.as_bytes());
        }

        println!("Handler: {} 404 Not Found", method);
        Ok(Self::create_404_response(req.version()).as_bytes())
    }
}
