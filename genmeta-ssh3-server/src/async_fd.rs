use std::{
    os::{
        fd::BorrowedFd,
        unix::prelude::{AsFd, OwnedFd},
    },
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use nix::{fcntl, unistd};
use tokio::io::{self, AsyncRead, AsyncWrite};

pub struct AsyncFd {
    fd: io::unix::AsyncFd<OwnedFd>,
}

impl AsyncFd {
    /// Create from an `OwnedFd` and set it to non-blocking mode.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let flags = fcntl::fcntl(fd.as_fd(), fcntl::F_GETFL).map_err(io::Error::from)?;
        let flags = fcntl::OFlag::from_bits_truncate(flags) | fcntl::OFlag::O_NONBLOCK;
        fcntl::fcntl(fd.as_fd(), fcntl::F_SETFL(flags)).map_err(io::Error::from)?;

        // 创建async_fd
        Ok(Self {
            fd: io::unix::AsyncFd::new(fd)?,
        })
    }

    pub fn split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        let fd = Arc::new(self);
        (OwnedReadHalf { fd: fd.clone() }, OwnedWriteHalf { fd })
    }
}

impl AsFd for AsyncFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn poll_read_impl(
    fd: &AsyncFd,
    cx: &mut Context<'_>,
    buf: &mut io::ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    loop {
        let mut read_ready = ready!(fd.fd.poll_read_ready(cx)?);
        match read_ready
            .try_io(|fd| unistd::read(fd, buf.initialize_unfilled()).map_err(io::Error::from))
        {
            Ok(Ok(n)) => {
                buf.set_filled(buf.filled().len() + n);
                return Poll::Ready(Ok(()));
            }
            Ok(Err(e)) => return Poll::Ready(Err(e)),
            Err(_would_block) => continue,
        }
    }
}

impl AsyncRead for AsyncFd {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        poll_read_impl(&self, cx, buf)
    }
}

pub struct OwnedReadHalf {
    fd: Arc<AsyncFd>,
}

impl AsFd for OwnedReadHalf {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        poll_read_impl(&self.fd, cx, buf)
    }
}

fn poll_write_impl(fd: &AsyncFd, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    loop {
        let mut write_ready = ready!(fd.fd.poll_write_ready(cx)?);
        match write_ready.try_io(|fd| unistd::write(fd, buf).map_err(io::Error::from)) {
            Ok(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Ok(Ok(n)) => return Poll::Ready(Ok(n)),
            Ok(Err(e)) => return Poll::Ready(Err(e)),
            Err(_would_block) => continue,
        }
    }
}

impl AsyncWrite for AsyncFd {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        poll_write_impl(&self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

pub struct OwnedWriteHalf {
    fd: Arc<AsyncFd>,
}

impl AsFd for OwnedWriteHalf {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        poll_write_impl(&self.fd, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}
