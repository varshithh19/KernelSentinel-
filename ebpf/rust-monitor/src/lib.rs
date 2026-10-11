//! Shared Data Structures between Rust eBPF Kernel Probes and User-Space Collectors
//! KernelSentinel Telemetry Protocol

pub const MAGIC_KSEN: u32 = 0x4B53454E; // "KSEN" in ASCII

pub const EVENT_TYPE_EXEC: u32 = 1;
pub const EVENT_TYPE_OPEN: u32 = 2;
pub const EVENT_TYPE_CONNECT: u32 = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EventHeader {
    pub magic: u32,
    pub event_type: u32,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessExecEvent {
    pub header: EventHeader,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileOpenEvent {
    pub header: EventHeader,
    pub filename: [u8; 256],
    pub flags: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetworkConnectEvent {
    pub header: EventHeader,
    pub daddr: u32,
    pub dport: u16,
    pub pad: u16,
}
