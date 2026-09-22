//! um-parttable IPC protocol -- shared between the partition-table
//! service and every client that needs to know where ITS partition
//! lives (e.g. um-cfs) without parsing GPT/MBR itself.
//!
//! This is the userspace-microkernel analog of what a monolithic
//! kernel (Linux, Windows) does in-kernel: the caller never re-parses
//! the partition table, it asks the one component that already did
//! and gets back a plain LBA range. Here that component is a trusted
//! system SERVICE (um-parttable) reached over IPC instead of a ring-0
//! kernel call -- same division of responsibility, different
//! mechanism, because this OS keeps ring 0 limited to code that
//! actually needs hardware privilege (port I/O, IRQs), and GPT/MBR
//! parsing needs neither.
//!
//! Single-message protocol, same shape as um-vfs's (see its abi crate
//! for the general pattern this mirrors).

#![cfg_attr(not(test), no_std)]
#![allow(missing_docs)]

pub const PARTTABLE_REQ_CAP:   u64 = 0x102;
pub const PARTTABLE_REPLY_CAP: u64 = 0x103;

pub const OP_REPLY_BIT: u32 = 0x80;

/// Sentinel type GUID meaning "this whole disk has no partition table
/// at all (blank/scratch disk) -- safe to use as one big partition
/// starting at LBA 0". Never a real GPT type GUID (those are actual
/// UUIDs; this is the all-0xFF pattern, which the GPT spec never
/// assigns). A disk protected by GPT or a protective MBR that simply
/// lacks a CruxFS partition is NOT tracked under this GUID -- only a
/// genuinely empty disk is, so a caller falling back to it can never
/// accidentally write over a real partition table.
pub const RAW_DISK_TYPE_GUID: [u8; 16] = [0xFF; 16];

/// Find the `index`-th partition (0-based, in scan order across every
/// disk this service found -- not necessarily disk-then-slot sorted,
/// but stable for the lifetime of this boot unless mkgpt/add_partition
/// change something) whose GPT type GUID matches `payload[0..2]` (16
/// bytes packed as two u64, little-endian halves of the raw on-disk
/// GUID bytes -- see `pack_guid`/`unpack_guid`). `index`=0 is "the
/// first match", same as this op's original single-disk behavior --
/// existing callers that never set payload[2] keep working unchanged.
///
///   request: payload[0..2] = type_guid (16 bytes), payload[2] = index
///   reply:   payload[0]=status (E_NOTFOUND if fewer than index+1 matches),
///            payload[1]=slot_id (the block-abi SLOT_ID_BASE+N to read/write),
///            payload[2]=starting_lba, payload[3]=size_lba (512-byte sectors)
pub const OP_FIND_PARTITION: u32 = 0x20;

/// (Re)initialize `slot_id` as a fresh, empty GPT: protective MBR +
/// primary/backup headers and entry arrays, zero partitions. THIS
/// DESTROYS ANY EXISTING PARTITION TABLE OR DATA ON THE DISK -- the
/// caller (um-shell's `part mkgpt`) is expected to have confirmed
/// with a human before sending this, the same way `mkfs`/`diskpart
/// clean` do.
///
///   request: payload[0]=slot_id
///   reply:   payload[0]=status
pub const OP_MKGPT: u32 = 0x21;

/// Add one partition to a disk that already has a GPT (see
/// OP_MKGPT). Picks the first gap at least `size_lba` sectors long
/// starting from the lowest usable LBA; `size_lba`=0 means "use all
/// remaining free space". The partition name is derived from
/// `type_guid` (CruxFS's type gets "crux-root"; anything else gets
/// "partition") -- there's no room left in one IPC message for an
/// arbitrary name too.
///
///   request: payload[0]=slot_id, payload[1..3]=type_guid, payload[3]=size_lba
///   reply:   payload[0]=status (E_NOSPC if no gap big enough),
///            payload[1]=starting_lba, payload[2]=size_lba assigned
pub const OP_ADD_PARTITION: u32 = 0x22;

// ── status codes (negative on error, POSIX errno) ───────────────────────
pub const E_OK:       i64 = 0;
pub const E_NOTFOUND: i64 = -2;
pub const E_IO:       i64 = -5;
pub const E_NOSPC:    i64 = -28;

// ── GUID packing ─────────────────────────────────────────────────────────

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
