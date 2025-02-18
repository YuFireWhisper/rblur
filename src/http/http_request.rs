use std::{
    collections::HashMap,
    io::{self},
    str::FromStr,
};

use http::{Method, Version};
use url::form_urlencoded;

#[derive(PartialEq, Debug)]
enum ParseState {
    RequestLine,
    Headers,
    Body,
    Complete,
    Error(String),
}

impl Default for ParseState {
    fn default() -> Self {
        Self::RequestLine
    }
}

#[derive(Default, Debug)]
pub struct HttpRequest {
    method: Method,
    path: String,
    version: Version,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    parse_state: ParseState,
    buffer: Vec<u8>,
    header_index: usize,
    body_bytes_read: usize,
}

impl HttpRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(&mut self, input: &[u8]) -> io::Result<bool> {
        if input.is_empty() {
            return Ok(true);
        }

        self.buffer.extend_from_slice(input);

        loop {
            match self.parse_state {
                ParseState::RequestLine => {
                    if !self.parse_request_line()? {
                        return Ok(true);
                    }
                }
                ParseState::Headers => {
                    if !self.parse_headers()? {
                        return Ok(true);
                    }
                }
                ParseState::Body => {
                    if !self.parse_body()? {
                        return Ok(true);
                    }
                }
                ParseState::Complete => {
                    return Ok(false);
                }
                ParseState::Error(ref err) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, err.clone()));
                }
            }
        }
    }

    fn parse_request_line(&mut self) -> io::Result<bool> {
        if let Some(line_end) = find_line_end(&self.buffer) {
            let line = &self.buffer[..line_end];
            let line_str = std::str::from_utf8(line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let parts: Vec<&str> = line_str.split_whitespace().collect();
            if parts.len() != 3 {
                self.parse_state = ParseState::Error("Invalid request line".into());
                return Ok(false);
            }

            self.method = Method::from_str(parts[0])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            self.path = parts[1].to_string();

            self.version = parse_http_version(parts[2]).unwrap_or_else(|| {
                self.parse_state = ParseState::Error("Invalid HTTP version".into());
                Version::HTTP_09
            });

            self.buffer.drain(..line_end + 2);
            self.parse_state = ParseState::Headers;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn parse_headers(&mut self) -> io::Result<bool> {
        while let Some(line_end) = find_line_end(&self.buffer[self.header_index..]) {
            let absolute_end = self.header_index + line_end;

            if line_end == 0 {
                self.buffer.drain(..self.header_index + 2);
                self.header_index = 0;

                self.parse_state = if self
                    .headers
                    .keys()
                    .any(|key| key.to_lowercase() == "content-length")
                {
                    ParseState::Body
                } else {
                    ParseState::Complete
                };

                return Ok(true);
            }

            let line = &self.buffer[self.header_index..absolute_end];
            let line_str = std::str::from_utf8(line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            if let Some((key, value)) = parse_header_line(line_str) {
                self.headers.insert(key.to_string(), value.to_string());
            }

            self.header_index = absolute_end + 2;
        }

        if self.buffer.len() - self.header_index > 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Headers too large",
            ));
        }

        Ok(false)
    }

    fn parse_body(&mut self) -> io::Result<bool> {
        let content_length: usize = match self
            .headers
            .iter()
            .find(|(key, _)| key.to_lowercase() == "content-length")
        {
            Some((_, len)) => len.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid Content-Length")
            })?,
            None => {
                self.parse_state = ParseState::Error("Missing Content-Length".into());
                return Ok(false);
            }
        };

        let bytes_remaining = content_length.saturating_sub(self.body_bytes_read);
        let bytes_available = self.buffer.len();

        if bytes_remaining > 0 && bytes_available > 0 {
            let bytes_to_read = bytes_remaining.min(bytes_available);
            self.body.extend_from_slice(&self.buffer[..bytes_to_read]);
            self.buffer.drain(..bytes_to_read);
            self.body_bytes_read += bytes_to_read;

            if self.body_bytes_read >= content_length {
                self.parse_state = ParseState::Complete;
            }
        }

        Ok(self.parse_state == ParseState::Complete)
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.parse_state, ParseState::Complete)
    }

    pub fn query_params(&self) -> HashMap<String, Vec<String>> {
        let mut params: HashMap<String, Vec<String>> = HashMap::new();
        if let Some(query_start) = self.path.find('?') {
            let query_string = &self.path[query_start + 1..];
            for (key, value) in form_urlencoded::parse(query_string.as_bytes()) {
                params
                    .entry(key.into_owned())
                    .or_default()
                    .push(value.into_owned());
            }
        }
        params
    }
}

pub fn http_version_to_string(version: &Version) -> &'static str {
    match *version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "Unknown",
    }
}

fn parse_http_version(version_str: &str) -> Option<Version> {
    let version_str = version_str.to_uppercase();

    match version_str.as_str() {
        "HTTP/0.9" => Some(Version::HTTP_09),
        "HTTP/1.0" => Some(Version::HTTP_10),
        "HTTP/1.1" => Some(Version::HTTP_11),
        "HTTP/2" | "HTTP/2.0" => Some(Version::HTTP_2),
        "HTTP/3" | "HTTP/3.0" => Some(Version::HTTP_3),
        _ => None, // Invalid version
    }
}

fn find_line_end(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|window| window == b"\r\n")
}

fn parse_header_line(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.splitn(2, ':');
    Some((parts.next()?.trim(), parts.next()?.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_line() {
        let mut request = HttpRequest::new();

        let input = b"GET /index.html HTTP/1.1\r\n";
        assert!(request.parse(input).unwrap());
        assert_eq!(*request.method(), Method::GET);
        assert_eq!(request.path(), "/index.html");
        assert_eq!(*request.version(), Version::HTTP_11);
    }

    #[test]
    fn test_parse_headers() {
        let mut request = HttpRequest::new();

        let input = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n";
        assert!(request.parse(input).unwrap());

        assert_eq!(request.headers().get("Host").unwrap(), "example.com");
        assert_eq!(request.headers().get("Content-Length").unwrap(), "5");
    }

    #[test]
    fn test_parse_body() {
        let mut request = HttpRequest::new();

        let part1 = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nHell";
        let part2 = b"o";

        assert!(request.parse(part1).unwrap());
        assert!(!request.is_complete());

        assert!(!request.parse(part2).unwrap());
        assert!(request.is_complete());

        assert_eq!(request.body(), b"Hello");
    }
}
