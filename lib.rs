//! um-parttable protocol and client -- shared between the partition-table
//! service and every process that needs to know where partitions live
//! (um-vfs, um-cfs) or to partition a disk (the installer), without
//! parsing GPT/MBR itself.
//!
//! This is the userspace-microkernel analog of what a monolithic kernel
//! (Linux, Windows) does in-kernel: the caller never re-parses the
//! partition table, it asks the one component that already did and gets
//! back a plain LBA range. Here that component is a system service
//! reached over IPC v2: each client has its own session (`connect`), so
//! replies never cross between clients.
//!
//! Who may do what:
//! - looking (`OP_PARTITION_AT`, `OP_FIND_PARTITION`, `OP_GENERATION`):
//!   any process -- where partitions lie is not a secret, like
//!   /proc/partitions;
//! - changing a disk (`OP_MKGPT`, `OP_ADD_PARTITION`): the request carries
//!   the disk itself, a device handle the client opened for writing and
//!   sent along (`disk_access()`); the service writes through that handle
//!   only, so a client can change exactly the disks it could write anyway
//!   (an administrator's elevated command), never through the service's
//!   own access to every disk.

#![cfg_attr(not(test), no_std)]
#![allow(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use runtime::channel::{self, Channel};
use runtime::devices::{Access, Device};
use runtime::syscall::Errno;
use zigbone_abi::ipc::Message;

/// The service's name (`channel::connect`).
pub const SERVICE: &[u8] = b"parttable";

/// Find the `index`-th partition (0-based, in scan order across every
/// disk) whose GPT type GUID matches.
///
///   request: payload[0..2] = type_guid (`pack_guid`), payload[2] = index
///   reply:   payload[0]=status (ENOENT if fewer than index+1 match),
///            payload[1]=slot_id (the block device to read/write),
///            payload[2]=starting_lba, payload[3]=size_lba (512-byte sectors)
pub const OP_FIND_PARTITION: u32 = 0x20;

/// (Re)initialize the disk as a fresh, empty GPT: protective MBR,
/// primary and backup headers and entry arrays, no partitions. THIS
/// DESTROYS THE EXISTING PARTITION TABLE -- the caller confirms with a
/// person first, as `mkfs` / `diskpart clean` do.
///
///   request: payload[0] = the disk (a transferred device handle, opened
///            for reading and writing)
///   reply:   payload[0]=status (EBADF: not a disk opened for writing)
pub const OP_MKGPT: u32 = 0x21;

/// Add one partition to a disk that has a GPT: into the first free gap
/// at least `size_lba` sectors long (gaps left by removed partitions
/// included); `size_lba`=0 takes the largest gap whole. The name follows
/// the type (CruxFS: "crux-root", anything else: "partition").
///
///   request: payload[0] = the disk (as for OP_MKGPT),
///            payload[1..3] = type_guid, payload[3] = size_lba
///   reply:   payload[0]=status (ENOSPC if no gap is big enough),
///            payload[1]=starting_lba, payload[2]=size_lba assigned
pub const OP_ADD_PARTITION: u32 = 0x22;

/// Hot plug: the device-set generation (`SYS_DEVICES_WAIT`) whose disks
/// the partition list already reflects. A client that saw the device set
/// change to generation G waits until this reaches G before looking for
/// partitions, so it never sees the list from before the change.
///
///   request: (none)
///   reply:   payload[0]=status, payload[1]=generation
pub const OP_GENERATION: u32 = 0x23;

/// The `index`-th partition of any type (0-based, across every disk):
/// for clients that look at what is inside (um-vfs probes each one for a
/// file system it can mount).
///
///   request: payload[0] = index
///   reply:   payload[0]=status (ENOENT past the last one),
///            payload[1]=slot_id, payload[2]=starting_lba,
///            payload[3]=size_lba, payload[4..6]=type GUID (pack_guid)
pub const OP_PARTITION_AT: u32 = 0x24;

/// GPT type of a CruxFS partition (on-disk byte order).
pub const CRUXFS_TYPE_GUID: [u8; 16] = [
    0xc6, 0xe6, 0x63, 0xf9, 0xa4, 0xd9, 0xac, 0x48, 0xaf, 0x85, 0xa1, 0xf4, 0xe2, 0x36, 0xda, 0x26,
];

/// GPT type of the EFI system partition (on-disk byte order).
pub const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

/// Type reported for a file system spanning a whole disk without a
/// partition table (most USB flash drives: FAT32, exFAT): the GPT
/// "Microsoft basic data" type.
pub const WHOLE_DISK_FS_TYPE_GUID: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

/// Type reported for a disk with no partition table and nothing
/// recognizable on it (a blank disk): the whole disk, from LBA 0. Never a
/// real GPT type (the all-0xFF pattern). A disk with a partition table
/// that merely lacks some partition is never reported this way, so a
/// caller using it cannot write over a real table.
pub const RAW_DISK_TYPE_GUID: [u8; 16] = [0xFF; 16];

/// Pack a raw 16-byte GUID into two little-endian u64 payload slots.
#[inline]
pub fn pack_guid(guid: &[u8; 16]) -> [u64; 2] {
    [
        u64::from_le_bytes(guid[0..8].try_into().unwrap()),
        u64::from_le_bytes(guid[8..16].try_into().unwrap()),
    ]
}

/// Inverse of `pack_guid`.
#[inline]
pub fn unpack_guid(lo: u64, hi: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&lo.to_le_bytes());
    out[8..16].copy_from_slice(&hi.to_le_bytes());
    out
}

// Reply status (payload[0]) is a system status from the error registry
// (zigbone_abi::errors): generic errors where they fit, the `parttable`
// facility for partition-table conditions.
pub use zigbone_abi::errors::{Error, Status, parttable as errors};

/// One partition: the block device (slot) and where on it, in 512-byte
/// sectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    pub slot: u64,
    pub start: u64,
    pub size: u64,
    pub type_guid: [u8; 16],
}

/// How to open a disk to partition it through the service.
pub const fn disk_access() -> Access {
    Access::READ_WRITE.transferable()
}

/// A session with the partition-table service.
pub struct PartTable(Channel);

impl PartTable {
    pub fn connect() -> Result<PartTable, Errno> {
        channel::connect(SERVICE).map(PartTable)
    }

    fn call(&self, op: u32, payload: [u64; 6]) -> Result<[u64; 6], Errno> {
        let mut m = Message::empty(op);
        m.payload = payload;
        let r = self.0.call(&m)?;
        let status = r.payload[0] as i64;
        if status < 0 { Err(status) } else { Ok(r.payload) }
    }

    /// Sends `disk` along (a duplicate: the caller keeps it).
    fn call_with_disk(&self, op: u32, disk: &Device, mut payload: [u64; 6]) -> Result<[u64; 6], Errno> {
        payload[0] = disk.handle() as u64;
        let mut m = Message::empty(op);
        m.payload = payload;
        self.0.send_handle_keep(&m, 0)?;
        let r = self.0.recv()?;
        let status = r.payload[0] as i64;
        if status < 0 { Err(status) } else { Ok(r.payload) }
    }

    /// The device-set generation the partition list reflects.
    pub fn generation(&self) -> Result<u64, Errno> {
        self.call(OP_GENERATION, [0; 6]).map(|p| p[1])
    }

    /// The `index`-th partition of any type (ENOENT past the last one).
    pub fn partition_at(&self, index: u64) -> Result<Partition, Errno> {
        let p = self.call(OP_PARTITION_AT, [index, 0, 0, 0, 0, 0])?;
        Ok(Partition { slot: p[1], start: p[2], size: p[3], type_guid: unpack_guid(p[4], p[5]) })
    }

    /// Every partition the service knows.
    pub fn partitions(&self) -> Vec<Partition> {
        (0..).map_while(|i| self.partition_at(i).ok()).collect()
    }

    /// The `index`-th partition of type `type_guid`.
    pub fn find(&self, type_guid: &[u8; 16], index: u32) -> Result<Partition, Errno> {
        let [g0, g1] = pack_guid(type_guid);
        let p = self.call(OP_FIND_PARTITION, [g0, g1, index as u64, 0, 0, 0])?;
        Ok(Partition { slot: p[1], start: p[2], size: p[3], type_guid: *type_guid })
    }

    /// Write an empty GPT to `disk` (opened with `disk_access()`).
    pub fn mkgpt(&self, disk: &Device) -> Result<(), Errno> {
        self.call_with_disk(OP_MKGPT, disk, [0; 6]).map(|_| ())
    }

    /// Add a partition of `type_guid`, `size_lba` sectors (0: the largest
    /// free gap); returns (starting_lba, size_lba).
    pub fn add_partition(&self, disk: &Device, type_guid: &[u8; 16], size_lba: u64) -> Result<(u64, u64), Errno> {
        let [g0, g1] = pack_guid(type_guid);
        self.call_with_disk(OP_ADD_PARTITION, disk, [0, g0, g1, size_lba, 0, 0]).map(|p| (p[1], p[2]))
    }
}
