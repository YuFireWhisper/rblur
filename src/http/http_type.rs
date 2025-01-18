use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub enum HttpMethod {
    Invalid,
    Get,
    Post,
    Head,
    Put,
    Delete,
}

impl Default for HttpMethod {
    fn default() -> Self {
        Self::Invalid
    }
}

impl FromStr for HttpMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "HEAD" => Ok(Self::Head),
            "PUT" => Ok(Self::Put),
            "DELETE" => Ok(Self::Delete),
            _ => Err(format!("Invalid HTTP method: {}", s)),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum HttpVersion {
    Invalid,
    Http1_1,
    Http2_0,
    Http3_0,
}

impl Default for HttpVersion {
    fn default() -> Self {
        Self::Invalid
    }
}

impl FromStr for HttpVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "HTTP/1.1" => Ok(HttpVersion::Http1_1),
            "HTTP/2" | "HTTP/2.0" | "H2" => Ok(HttpVersion::Http2_0),
            "HTTP/3" | "HTTP/3.0" | "H3" => Ok(HttpVersion::Http3_0),
            _ => Err(format!("Invalid HTTP version: {}", s)),
        }
    }
}
