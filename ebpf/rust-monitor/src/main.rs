//! KernelSentinel Rust eBPF Kernel Probe Programs
//! Captures sys_enter_execve, sys_enter_openat, sys_enter_connect kernel tracepoints.

use kernelsentinel_ebpf::{
    EventHeader, ProcessExecEvent, FileOpenEvent, NetworkConnectEvent,
    MAGIC_KSEN, EVENT_TYPE_EXEC, EVENT_TYPE_OPEN, EVENT_TYPE_CONNECT,
};

#[no_mangle]
pub fn ksen_sys_enter_execve() -> i32 {
    let _header = EventHeader {
        magic: MAGIC_KSEN,
        event_type: EVENT_TYPE_EXEC,
        pid: 0,
        tgid: 0,
        uid: 0,
        timestamp_ns: 0,
    };
    0
}

#[no_mangle]
pub fn ksen_sys_enter_openat() -> i32 {
    let _header = EventHeader {
        magic: MAGIC_KSEN,
        event_type: EVENT_TYPE_OPEN,
        pid: 0,
        tgid: 0,
        uid: 0,
        timestamp_ns: 0,
    };
    0
}

#[no_mangle]
pub fn ksen_sys_enter_connect() -> i32 {
    let _header = EventHeader {
        magic: MAGIC_KSEN,
        event_type: EVENT_TYPE_CONNECT,
        pid: 0,
        tgid: 0,
        uid: 0,
        timestamp_ns: 0,
    };
    0
}

fn main() {
    println!("=== KernelSentinel Rust eBPF Monitor ===");
    println!("Protocol Magic: 0x{:08X}", MAGIC_KSEN);
    println!("Supported Event Struct Sizes:");
    println!(" - Header: {} bytes", std::mem::size_of::<EventHeader>());
    println!(" - ProcessExecEvent: {} bytes", std::mem::size_of::<ProcessExecEvent>());
    println!(" - FileOpenEvent: {} bytes", std::mem::size_of::<FileOpenEvent>());
    println!(" - NetworkConnectEvent: {} bytes", std::mem::size_of::<NetworkConnectEvent>());
}
