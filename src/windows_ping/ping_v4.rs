use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr};
use windows::Win32::Foundation::{HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{ICMP_ECHO_REPLY, IcmpHandle, IcmpSendEcho2, IP_OPTION_INFORMATION};
use crate::windows_ping::{IcmpEcho, PingRawReply};

impl IcmpEcho for Ipv4Addr {
    fn send(&self, handle: IcmpHandle, event: Option<HANDLE>, data: *const c_void, data_len: u16, options: *const IP_OPTION_INFORMATION, reply_buffer: *mut c_void, reply_buffer_len: u32, timeout: u32) -> u32 {
        unsafe {
            let destination_address = *((&self.octets() as *const u8) as *const u32);
            IcmpSendEcho2(handle, event, None, None, destination_address, data, data_len as u16, Some(options), reply_buffer, reply_buffer_len, timeout)
        }
    }
    fn create_raw_reply(&self, reply: *mut u8) -> PingRawReply {
        let reply = unsafe { *(reply as *const ICMP_ECHO_REPLY) };
    
        // Handle Network Byte Order (Big Endian)
        let addr_ptr = &reply.Address as *const u32 as *const [u8; 4];
        let addr = u32::from_be_bytes(unsafe { *addr_ptr });
    
        // Extract the reply data
        let data_ptr = reply.Data as *const u8;
        let data_len = reply.DataSize as usize;
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len).to_vec() };
    
        PingRawReply {
            address: IpAddr::V4(Ipv4Addr::from(addr)),
            status: reply.Status,
            rtt: reply.RoundTripTime,
            data, // Populate the data field
        }
    }
    
}
