use crate::http::{http_request::HttpRequest, http_response::HttpResponse};
use http::{Method, StatusCode, Version};
use std::collections::HashMap;
use thiserror::Error;

type ProcessorResult<T> = Result<T, ProcessorError>;

#[derive(Debug, Error)]
pub enum ProcessorError {
    #[error("Parsing request failed")]
    ParseError,
}

type ProcessorResponse = Vec<u8>;

pub trait Processor {
    fn process(&self, request: Vec<u8>) -> ProcessorResult<ProcessorResponse>;
}

pub type HttpHandler = Box<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static>;

#[derive(Default)]
pub struct HttpProcessor {
    handlers: HashMap<(String, StatusCode, &'static Method), HttpHandler>,
}

impl HttpProcessor {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    pub fn add_handler(
        &mut self,
        path: String,
        code: StatusCode,
        method: &'static Method,
        handler: HttpHandler,
    ) {
        self.handlers.insert((path, code, method), handler);
    }

    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    pub fn create_404_response(http_version: &Version) -> HttpResponse {
        let mut response = HttpResponse::new();
        response.set_status_line(*http_version, StatusCode::NOT_FOUND);
        response.set_header("Content-Type", "text/plain");
        response.set_body("404 Not Found");
        response
    }
}

impl Processor for HttpProcessor {
    fn process(&self, request: Vec<u8>) -> ProcessorResult<ProcessorResponse> {
        for (path, code, method) in self.handlers.keys() {
            println!("Handler: {} {} {}", method, code, path);
        }

        let mut req = HttpRequest::new();
        req.parse(&request)
            .map_err(|_| ProcessorError::ParseError)?;

        let clean_path = req.path().split('?').next().unwrap().to_owned();
        let method = req.method();
        println!("Request: {} {}", method, clean_path);

        let handler = self
            .handlers
            .get(&(clean_path.clone(), StatusCode::OK, method))
            .or_else(|| {
                self.handlers
                    .get(&(clean_path, StatusCode::OK, &Method::OPTIONS))
            });

        if *method == Method::OPTIONS && handler.is_none() {
            let mut response = HttpResponse::new();
            response.set_status_line(*req.version(), StatusCode::OK);
            response.set_header("Content-Type", "text/plain");
            response.set_body("");
            return Ok(response.as_bytes());
        }

        let response = if let Some(handler) = handler {
            handler(&req)
        } else {
            Self::create_404_response(req.version())
        };

        println!("Response: {}", response.status_line);
        println!("Header: {}", response.header);
        Ok(response.as_bytes())
    }
}
