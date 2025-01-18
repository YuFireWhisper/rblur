use std::{collections::HashMap, io, os::fd::RawFd};

#[cfg(target_os = "linux")]
pub mod epoll;

#[derive(Hash, Eq, PartialEq)]
pub enum EventType {
    Read,
    Write,
    Close,
    Error,
}

pub trait EventHandler: Send + Sync {
    fn handle(&self, fd: RawFd, event_type: EventType) -> io::Result<()>;
}

pub trait PollImpl {
    fn add(&mut self, fd: RawFd) -> io::Result<()>;
    fn remove(&mut self, fd: RawFd) -> io::Result<()>;
    fn poll(&mut self, timeout: Option<std::time::Duration>)
        -> io::Result<Vec<(RawFd, EventType)>>;
}

pub struct Poll {
    implementation: Box<dyn PollImpl>,
    handlers: HashMap<RawFd, HashMap<EventType, Box<dyn EventHandler>>>,
}

impl Poll {
    pub fn new() -> io::Result<Self> {
        let implementation: Box<dyn PollImpl> = {
            #[cfg(target_os = "linux")]
            {
                Box::new(epoll::EPoll::new()?)
            }
        };

        Ok(Poll {
            implementation,
            handlers: HashMap::new(),
        })
    }

    pub fn register_handler(
        &mut self,
        fd: RawFd,
        event_type: EventType,
        handler: Box<dyn EventHandler>,
    ) -> io::Result<()> {
        self.handlers
            .entry(fd)
            .or_default()
            .insert(event_type, handler);

        if !self.handlers.contains_key(&fd) {
            self.implementation.add(fd)?;
        }
        Ok(())
    }

    pub fn unregister(&mut self, fd: RawFd, event_type: EventType) -> io::Result<()> {
        if let Some(handlers) = self.handlers.get_mut(&fd) {
            handlers.remove(&event_type);
            if handlers.is_empty() {
                self.handlers.remove(&fd);
                self.implementation.remove(fd)?;
            }
        }
        Ok(())
    }

    pub fn poll(&mut self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        let events = self.implementation.poll(timeout)?;

        for (fd, event_type) in events {
            if let Some(handlers) = self.handlers.get(&fd) {
                if let Some(handler) = handlers.get(&event_type) {
                    handler.handle(fd, event_type)?;
                }
            }
        }

        Ok(())
    }
}
