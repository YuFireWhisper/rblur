use std::{io, os::fd::RawFd};

use super::{EventType, PollImpl};

pub struct EPoll {
    epoll_fd: RawFd,
    events: Vec<libc::epoll_event>,
}

impl EPoll {
    pub fn new() -> io::Result<Self> {
        let epoll_fd = unsafe { libc::epoll_create1(0) };
        if epoll_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut events = Vec::with_capacity(1024);
        events.resize(1024, unsafe { std::mem::zeroed() });

        Ok(Self {
            epoll_fd,
            events,
        })
    }
}

impl PollImpl for EPoll {
    fn add(&mut self, fd: RawFd) -> io::Result<()> {
        let mut event: libc::epoll_event = unsafe { std::mem::zeroed() };
        event.events = (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLERR | libc::EPOLLET) as u32;
        event.u64 = fd as u64;

        if unsafe { libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut event) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn remove(&mut self, fd: RawFd) -> io::Result<()> {
        if unsafe { libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) }
            < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn poll(
        &mut self,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<Vec<(RawFd, EventType)>> {
        let timeout_ms = timeout.map_or(-1, |t| t.as_millis() as i32);
        let mut events = Vec::new();

        let n =
            unsafe { libc::epoll_wait(self.epoll_fd, self.events.as_mut_ptr(), 1024, timeout_ms) };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        for i in 0..n as usize {
            let event = unsafe { self.events.get_unchecked(i) };
            let fd = event.u64 as RawFd;

            if (event.events & libc::EPOLLIN as u32) != 0 {
                println!("read");
                events.push((fd, EventType::Read));
            }
            if (event.events & libc::EPOLLOUT as u32) != 0 {
                println!("write");
                events.push((fd, EventType::Write));
            }
            if (event.events & (libc::EPOLLERR as u32 | libc::EPOLLHUP as u32)) != 0 {
                println!("error");
                events.push((fd, EventType::Error));
            }
        }

        Ok(events)
    }
}
