use std::sync::atomic::AtomicPtr;

pub mod http_location;
pub mod http_manager;
pub mod http_request;
pub mod http_response;
pub mod http_server;
pub mod http_type;

fn find_line_end(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|window| window == b"\r\n")
}

fn parse_header_line(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.splitn(2, ':');
    Some((parts.next()?.trim(), parts.next()?.trim()))
}

pub fn get_context_u8<T>(ctx: &mut T) -> AtomicPtr<u8> {
    AtomicPtr::new(ctx as *mut T as *mut u8)
}
