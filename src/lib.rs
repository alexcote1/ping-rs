//! Provide ICMP Echo (ping) functionality for both Windows and Linux. This library does not need root/admin privilege for pinging.
//! It provides sync and async ping functions: [`send_ping`] and [`send_ping_async`].
//!
//! Linux version still does not support "Do not Fragment" flag yet.
//!
//! # Usage Example
//!
//! An example is also provided in `/bin/sample_ping.rs`
//!
//! ## Synchronous ping
//!
//! ```rust,no_run
//! use std::time::Duration;
//!
//! fn main(){
//!     let addr = "8.8.8.8".parse().unwrap();
//!     let data = [1,2,3,4];  // ping data
//!     let timeout = Duration::from_secs(1);
//!     let options = ping_rs::PingOptions { ttl: 128, dont_fragment: true };
//!     let result = ping_rs::send_ping(&addr, timeout, &data, Some(&options));
//!     match result {
//!         Ok(reply) => println!("Reply from {}: data={} bytes={} time={}ms TTL={}", reply.address, ,reply.data data.len(), reply.rtt, options.ttl),
//!         Err(e) => println!("{:?}", e)
//!     }
//! }
//! ```
//!
//! ## Asynchronous ping
//!
//! Note that `futures` crate is used in this example. Also, data passed in the function has to be wrapped with `Arc` because in Windows' implementation
//! the address of this data will be passed to Win32 API.
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! fn main(){
//!     let addr = "8.8.8.8".parse().unwrap();
//!     let data = [1,2,3,4];  // ping data
//!     let data_arc = Arc::new(&data[..]);
//!     let timeout = Duration::from_secs(1);
//!     let options = ping_rs::PingOptions { ttl: 128, dont_fragment: true };
//!     let future = ping_rs::send_ping_async(&addr, timeout, data_arc, Some(&options));
//!     let result = futures::executor::block_on(future);
//!     match result {
//!         Ok(reply) => println!("Reply from {}: data={} bytes={} time={}ms TTL={}", reply.address, ,reply.data data.len(), reply.rtt, options.ttl),
//!         Err(e) => println!("{:?}", e)
//!     }
//! }
//! ```

mod windows_ping;
mod linux_ping;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tower::Service;
use futures::future::BoxFuture;
use tonic::transport::Uri;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::pin::Pin;


/// Contains constant values represent general errors.
#[allow(non_snake_case)]
pub mod IpStatus {
    #![allow(non_upper_case_globals)]

    pub type Type = u32;
    pub const Success: Type = 0;
    //BufferTooSmall = 11000 + 1;

    pub const DestinationNetworkUnreachable: Type = 11000 + 2;
    pub const DestinationHostUnreachable: Type = 11000 + 3;
    pub const DestinationProtocolUnreachable: Type = 11000 + 4;
    pub const DestinationPortUnreachable: Type = 11000 + 5;
    pub const DestinationProhibited: Type = 11000 + 19;

    pub const NoResources: Type = 11000 + 6;
    pub const BadOption: Type = 11000 + 7;
    pub const HardwareError: Type = 11000 + 8;
    pub const PacketTooBig: Type = 11000 + 9;
    pub const TimedOut: Type = 11000 + 10;
    pub const BadRoute: Type = 11000 + 12;

    pub const TtlExpired: Type = 11000 + 13;
    pub const TtlReassemblyTimeExceeded: Type = 11000 + 14;

    pub const ParameterProblem: Type = 11000 + 15;
    pub const SourceQuench: Type = 11000 + 16;
    pub const BadDestination: Type = 11000 + 18;

    pub const DestinationUnreachable: Type = 11000 + 40;
    pub const TimeExceeded: Type = 11000 + 41;
    pub const BadHeader: Type = 11000 + 42;
    pub const UnrecognizedNextHeader: Type = 11000 + 43;
    pub const IcmpError: Type = 11000 + 44;
    pub const DestinationScopeMismatch: Type = 11000 + 45;

    // for example, no network interfaces are suitable to route the ping package.
    pub const GeneralFailure: Type = 11000 + 50;
}

#[derive(Debug, Clone)]
pub struct PingOptions {
    /// Package TTL
    pub ttl: u8,

    /// Socket's Dont Fragment
    pub dont_fragment: bool
}
impl std::fmt::Display for PingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for PingError {}

/// Ping reply contains the destination address (from ICMP reply) and Round-Trip Time
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PingReply {
    /// Destination address from ICMP reply
    pub address: IpAddr,
    /// Round-Trip Time in milliseconds
    pub rtt: u32,
    pub data: Vec<u8>,
}

/// Ping errors
#[derive(Debug, Clone)]
pub enum PingError {
    /// Bad request parameters
    BadParameter(&'static str),

    /// Unspecific OS errors
    OsError(u32, String),

    /// General Ping errors
    IpError(IpStatus::Type),

    /// Ping timed out
    TimedOut,

    /// I/O async pending
    IoPending,

    /// size of data buffer for ping is too big. The first parameter is the maximum allowed size.
    DataSizeTooBig(usize),
}

impl From<io::Error> for PingError {
    fn from(value: io::Error) -> Self {
        if value.kind() == io::ErrorKind::WouldBlock { PingError::IoPending }
        else { PingError::OsError(value.raw_os_error().unwrap_or(-1) as u32, value.to_string()) }
    }
}

pub type Result<T> = std::result::Result<T, PingError>;
pub type PingApiOutput = Result<PingReply>;

#[cfg(windows)]
use windows_ping as ping_mod;

#[cfg(unix)]
use linux_ping as ping_mod;

/// Send ICMP Echo package (ping) to the given address.
#[inline(always)]
pub fn send_ping(addr: &IpAddr, timeout: Duration, data: &[u8], options: Option<&PingOptions>) -> PingApiOutput {
    ping_mod::send_ping(addr, timeout, data, options)
}

/// Asynchronously schedule ICMP Echo package (ping) to the given address. Note that some parameter signatures are different
/// from [`send_ping`] function, as the caller should manage those parameters' lifetime.
#[inline(always)]
pub async fn send_ping_async(addr: &IpAddr, timeout: Duration, data: Arc<&[u8]>, options: Option<&PingOptions>) -> PingApiOutput {
    ping_mod::send_ping_async(addr, timeout, data, options).await
}

#[derive(Clone)]
pub struct IcmpConnector {
    target_addr: IpAddr,
    options: Option<PingOptions>,
}

impl IcmpConnector {
    pub fn new(target_addr: IpAddr, options: Option<PingOptions>) -> Self {
        Self {
            target_addr,
            options,
        }
    }
}


impl Service<Uri> for IcmpConnector {
    type Response = IcmpStream;
    type Error = PingError;
    type Future = BoxFuture<'static, Result<Self::Response>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
    

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let target_addr = self.target_addr;
        let options = self.options.clone();

        Box::pin(async move {
            let stream = IcmpStream::new(target_addr, options.unwrap_or_else(|| PingOptions { ttl: 64, dont_fragment: false })).await?;
            Ok(stream)
        })
    }
}








/// Simulated ICMP Stream structure
pub struct IcmpStream {
    target_addr: IpAddr,
    options: PingOptions,
    read_buffer: Vec<u8>,  // Buffer to store replies
}

impl IcmpStream {
    pub async fn new(target_addr: IpAddr, options: PingOptions) -> io::Result<Self> {
        Ok(Self {
            target_addr,
            options,
            read_buffer: Vec::new(),
        })
    }

    /// Send a ping request asynchronously and store the reply in the read buffer
    pub async fn send(&mut self, data: &[u8], timeout: Duration) -> io::Result<()> {
        let data_arc = Arc::new(data);
        let result = send_ping_async(&self.target_addr, timeout, data_arc, Some(&self.options)).await;
    
        match result {
            Ok(reply) => {
                self.read_buffer.extend(reply.data);
                Ok(())
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e))),
        }
    }
}

impl AsyncRead for IcmpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_buffer.is_empty() {
            return Poll::Pending; // No data available yet
        }

        let available = self.read_buffer.len();
        let to_copy = buf.remaining().min(available);
        let data: Vec<u8> = self.read_buffer.drain(0..to_copy).collect();
        buf.put_slice(&data);

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for IcmpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let timeout = Duration::from_secs(1); // Example timeout
        let options = self.options.clone();
        let addr = self.target_addr;
        let data = buf.to_vec();

        tokio::spawn(async move {
            let data_arc = Arc::new(data.as_slice());
            let _ = send_ping_async(&addr, timeout, data_arc, Some(&options)).await;
        });

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}