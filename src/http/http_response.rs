use http::{StatusCode, Version};

use super::http_request::http_version_to_string;

#[derive(Default, PartialEq)]
pub struct HttpResponse {
    pub status_line: String,
    pub header: String,
    pub body: String,
}

impl HttpResponse {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_status_line(&mut self, version: Version, status_code: StatusCode) -> &mut Self {
        let message = status_code.canonical_reason().unwrap();
        self.status_line = format!(
            "{} {} {}\r\n",
            http_version_to_string(&version),
            status_code,
            message
        );

        self
    }

    pub fn set_header(&mut self, key: &str, value: &str) -> &mut Self {
        self.header.push_str(key);
        self.header.push_str(": ");
        self.header.push_str(value);
        self.header.push_str("\r\n");

        self
    }

    pub fn set_body(&mut self, body: &str) -> &mut Self {
        self.body.push_str("\r\n");
        self.body.push_str(body);

        self
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(self.status_line.as_bytes());
        response.extend_from_slice(self.header.as_bytes());
        response.extend_from_slice(self.body.as_bytes());
        response
    }
}

pub fn get_content_type(path: &str) -> &'static str {
    path.split('.')
        .last()
        .map(|ext| match ext.to_lowercase().as_str() {
            "html" => "text/html",
            "css" => "text/css",
            "js" => "application/javascript",
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "gif" => "image/gif",
            "svg" => "image/svg+xml",
            "json" => "application/json",
            "txt" => "text/plain",
            _ => "application/octet-stream",
        })
        .unwrap_or("application/octet-stream")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_status_line() {
        let mut response = HttpResponse::new();
        response.set_status_line(Version::HTTP_11, StatusCode::OK);

        assert_eq!(response.status_line, "HTTP/1.1 200 OK".to_string());
    }
}
