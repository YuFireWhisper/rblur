pub mod http_request;
pub mod http_type;

fn find_line_end(buf: &[u8]) -> Option<usize> {
    buf.windows(2)
        .position(|window| window == b"\r\n")
}

fn parse_header_line(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.splitn(2, ':');
    Some((
        parts.next()?.trim(),
        parts.next()?.trim(),
    ))
}
