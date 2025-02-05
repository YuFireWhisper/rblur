use crate::http::{http_request::HttpRequest, http_response::HttpResponse, http_type::HttpVersion};
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

type HttpHandler = Box<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static>;

#[derive(Default)]
pub struct HttpProcessor {
    handlers: HashMap<(String, u32), HttpHandler>,
}

impl HttpProcessor {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    pub fn add_handler(&mut self, path: String, code: u32, handler: HttpHandler) {
        self.handlers.insert((path, code), handler);
    }

    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    pub fn create_404_response(http_version: &HttpVersion) -> HttpResponse {
        let mut response = HttpResponse::new();
        response.set_status_line(http_version.clone(), 404);
        response.set_header("Content-Type", "text/plain");
        response.set_body("404 Not Found");
        response
    }
}

impl Processor for HttpProcessor {
    fn process(&self, request: Vec<u8>) -> ProcessorResult<ProcessorResponse> {
        let req = {
            let mut req = HttpRequest::new();
            req.parse(&request).map_err(|_| ProcessorError::ParseError)?;
            req
        };

        let handler = self.handlers.get(&(req.path().to_string(), 200));

        let response = match handler {
            Some(handler) => handler(&req),
            None => Self::create_404_response(req.version()),
        };

        Ok(response.as_bytes())
    }
}
