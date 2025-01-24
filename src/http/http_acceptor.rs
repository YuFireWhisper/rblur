use std::{io, net::TcpListener, os::fd::AsRawFd, sync::Arc};

use super::reactor_pool::ReactorPool;

pub struct HttpAcceptor {
    listener: TcpListener,
    reactor_pool: Arc<ReactorPool>,
}

impl HttpAcceptor {
    pub fn new(addr: &str, reactor_pool: Arc<ReactorPool>) -> Self {
        let listener = TcpListener::bind(addr).unwrap();
        listener.set_nonblocking(true).unwrap();

        Self {
            listener,
            reactor_pool,
        }
    }

    pub fn start(&self) {
        loop {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    let fd = stream.as_raw_fd().to_string();
                    println!("New connection from: {addr}, fd: {fd}");
                    if let Err(e) = self.reactor_pool.accept_connection(stream) {
                        eprintln!("Error accepting connection: {}", e);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                    continue;
                }
            }
        }
    }
}
