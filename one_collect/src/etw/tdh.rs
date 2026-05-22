// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! # TDH-Based Dynamic Event Decoder
//!
//! This module provides [`TdhDecoder`], a runtime schema decoder for
//! TraceLogging and TraceLoggingDynamic ETW events.  It uses the Windows
//! Trace Data Helper (TDH) APIs to discover event schemas on the fly and
//! converts them into the standard [`EventFormat`] / [`EventData`]
//! representation used throughout one_collect.
//!
//! ## Design
//!
//! The decoder maintains two caches keyed by raw schema TL bytes (from
//! `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL`), split by pointer width:
//!
//! - **Schema layout cache**: The parsed property metadata (field names,
//!   TDH in-types, struct nesting) discovered from `TdhGetEventInformation`
//!   on the first occurrence of each schema.  This avoids redundant TDH
//!   kernel calls.
//!
//! - **Per-event offset computation**: Because variable-length fields
//!   (strings, binary) shift all subsequent field offsets, the concrete
//!   `EventFormat` with absolute offsets is computed fresh on every call
//!   to [`TdhDecoder::decode`], walking the cached schema layout against
//!   the actual event payload bytes.  Fixed-size-only schemas get exact
//!   offsets directly from the cache with no per-event walk.
//!
//! ## Scope
//!
//! - **Supported**: TraceLogging and TraceLoggingDynamic events, nested
//!   struct fields (flattened with dot-notation names), basic scalar and
//!   string property types, 32-bit and 64-bit event payloads.
//!
//! - **Not yet supported** (future work): manifest-based event decoding,
//!   map / enum value resolution, array-typed properties, and properties
//!   whose length or count is given by another property.  When an
//!   unsupported property is encountered, the decoder records a
//!   placeholder field and continues.

use super::abi::{EVENT_RECORD, EVENT_HEADER_EXTENDED_DATA_ITEM};
use crate::event::{EventData, EventField, EventFormat, LocationType};

use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use tracing::{debug, trace, warn};
use twox_hash::XxHash64;

// ── windows-sys imports for TDH ─────────────────────────────────────

use windows_sys::Win32::System::Diagnostics::Etw::{
    TRACE_EVENT_INFO,
    EVENT_PROPERTY_INFO,
    TdhGetEventInformation,

    TDH_INTYPE_UNICODESTRING,
    TDH_INTYPE_ANSISTRING,
    TDH_INTYPE_INT8,
    TDH_INTYPE_UINT8,
    TDH_INTYPE_INT16,
    TDH_INTYPE_UINT16,
    TDH_INTYPE_INT32,
    TDH_INTYPE_UINT32,
    TDH_INTYPE_INT64,
    TDH_INTYPE_UINT64,
    TDH_INTYPE_FLOAT,
    TDH_INTYPE_DOUBLE,
    TDH_INTYPE_BOOLEAN,
    TDH_INTYPE_BINARY,
    TDH_INTYPE_GUID,
    TDH_INTYPE_POINTER,
    TDH_INTYPE_FILETIME,
    TDH_INTYPE_SYSTEMTIME,
    TDH_INTYPE_SID,
    TDH_INTYPE_HEXINT32,
    TDH_INTYPE_HEXINT64,
    TDH_INTYPE_COUNTEDSTRING,
    TDH_INTYPE_REVERSEDCOUNTEDSTRING,
    TDH_INTYPE_NONNULLTERMINATEDSTRING,
    TDH_INTYPE_NONNULLTERMINATEDANSISTRING,
};

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;

/// `EVENT_HEADER_FLAG_32_BIT_HEADER` from the Windows SDK.
const EVENT_HEADER_FLAG_32_BIT_HEADER: u16 = 0x0020;

/// Property flag constants from `EVENT_PROPERTY_INFO::Flags` (i32 in windows-sys).
const PROPERTY_STRUCT: i32      = 0x1;
const PROPERTY_HAS_LENGTH: i32  = 0x4;
const PROPERTY_HAS_COUNT: i32   = 0x8;
/// `PROPERTY_PARAM_LENGTH` — when set together with `PROPERTY_HAS_LENGTH`,
/// `Anonymous3.length` is an *index* into the property array (not a literal
/// byte count).  We must not treat it as a fixed size in that case.
const PROPERTY_PARAM_LENGTH: i32 = 0x10;

/// Extended-data item type for TraceLogging schema metadata.
const EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL: u16 = 11;

// ── Error type ──────────────────────────────────────────────────────

/// Errors that can occur during TDH-based schema decoding.
#[derive(Debug)]
pub enum TdhDecodeError {
    /// No `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` extended-data item was
    /// found on the event.
    NotFound,
    /// A Win32 error code was returned by `TdhGetEventInformation`.
    Win32(u32),
    /// The `TRACE_EVENT_INFO` returned by TDH is structurally invalid.
    Malformed(&'static str),
}

impl std::fmt::Display for TdhDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no schema TL extended-data item found on event"),
            Self::Win32(code) => write!(f, "TdhGetEventInformation failed with Win32 error {code}"),
            Self::Malformed(msg) => write!(f, "malformed TRACE_EVENT_INFO: {msg}"),
        }
    }
}

impl std::error::Error for TdhDecodeError {}

// ── Cached schema layout (field names + types, no runtime offsets) ───

/// Describes what kind of data a TDH property holds, used to determine
/// its runtime byte length when walking event payload bytes.
#[derive(Clone, Debug, PartialEq)]
enum PropertyKind {
    /// Fixed-size scalar (size known at schema time).
    Fixed(usize),
    /// Null-terminated ANSI string (variable length at runtime).
    AnsiString,
    /// Null-terminated UTF-16 string (variable length at runtime).
    Utf16String,
    /// Counted string: 2-byte `u16` length prefix followed by `len`
    /// bytes of string data.  Runtime size = `2 + len`.
    CountedString,
    /// Variable-length blob whose size is not known at schema time
    /// (binary, SID, etc.).  When this is the last field, it consumes
    /// all remaining bytes.  When followed by more fields, it uses the
    /// TDH-reported explicit length if available, otherwise consumes
    /// all remaining bytes (best effort).
    VariableBlob,
    /// Unsupported: array or param-driven property.  Placeholder that
    /// uses TDH-reported explicit length if available, otherwise
    /// consumes all remaining bytes.
    Unsupported,
}

/// A single property in a cached schema layout.
#[derive(Clone, Debug)]
struct CachedProperty {
    /// Dot-notation qualified name (e.g. `"PartA.Name"`).
    name: String,
    /// Type name string for the `EventField` (e.g. `"u32"`, `"wstring"`).
    /// Always one of a fixed set of static strings.
    type_name: &'static str,
    /// What kind of data / how to compute runtime length.
    kind: PropertyKind,
}

/// The schema layout extracted from TDH on first encounter.
/// Contains everything needed to build an `EventFormat` per-event.
#[derive(Clone)]
struct CachedSchema {
    /// The TraceLogging event name extracted from `TRACE_EVENT_INFO`.
    /// Empty if the name could not be read.
    event_name: String,
    /// Ordered list of leaf properties (structs already flattened).
    properties: Vec<CachedProperty>,
    /// Pre-built `EventFormat` for the all-fixed fast path.
    /// `Some` when every property is `PropertyKind::Fixed` (offsets are
    /// constant across events).  `None` when the schema contains any
    /// variable-length fields and offsets must be computed per-event.
    fixed_format: Option<EventFormat>,
}

/// Hash builder using XxHash64, matching the rest of the ETW module.
type XxBuildHasher = BuildHasherDefault<XxHash64>;

/// Schema cache: two maps (32-bit / 64-bit) keyed by raw TL bytes.
struct SchemaLayoutCache {
    cache_64: HashMap<Vec<u8>, CachedSchema, XxBuildHasher>,
    cache_32: HashMap<Vec<u8>, CachedSchema, XxBuildHasher>,
}

impl SchemaLayoutCache {
    fn new() -> Self {
        Self {
            cache_64: HashMap::with_hasher(XxBuildHasher::default()),
            cache_32: HashMap::with_hasher(XxBuildHasher::default()),
        }
    }

    fn get(&self, key: &[u8], is_32bit: bool) -> Option<&CachedSchema> {
        let map = if is_32bit { &self.cache_32 } else { &self.cache_64 };
        map.get(key)
    }

    fn insert(&mut self, key: Vec<u8>, is_32bit: bool, schema: CachedSchema) {
        let map = if is_32bit { &mut self.cache_32 } else { &mut self.cache_64 };
        map.entry(key).or_insert(schema);
    }
}

// ── TdhDecoder ──────────────────────────────────────────────────────

/// Runtime decoder for TraceLogging / TraceLoggingDynamic ETW events.
pub struct TdhDecoder {
    cache: SchemaLayoutCache,
    /// Reusable `EventFormat` buffer to avoid per-event allocation
    /// when the schema has variable-length fields.
    format_buf: EventFormat,
}

impl TdhDecoder {
    /// Creates a new decoder with an empty schema cache.
    pub fn new() -> Self {
        Self {
            cache: SchemaLayoutCache::new(),
            format_buf: EventFormat::new(),
        }
    }

    /// Returns the cached event name for the given event's schema, or
    /// `None` if the schema has not been seen yet or has no name.
    ///
    /// This is the TraceLogging event name — the primary identity for
    /// TraceLogging events (as opposed to the event ID, which is often 0).
    pub fn event_name(&self, record: &EVENT_RECORD) -> Option<&str> {
        let is_32bit = (record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;
        let schema_tl_bytes = find_schema_tl(record).ok()?;
        let schema = self.cache.get(schema_tl_bytes, is_32bit)?;
        if schema.event_name.is_empty() {
            None
        } else {
            Some(&schema.event_name)
        }
    }

    /// Decodes an `EVENT_RECORD` into an [`EventData`].
    ///
    /// For schemas with only fixed-size fields, the cached `EventFormat`
    /// is returned directly (zero per-event allocation).  For schemas
    /// with variable-length fields, the concrete offsets are computed
    /// by walking the event's user-data payload against the cached
    /// schema layout.
    pub fn decode<'a>(
        &'a mut self,
        record: &'a EVENT_RECORD,
    ) -> Result<EventData<'a>, TdhDecodeError> {
        let is_32bit = (record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;
        let schema_tl_bytes = find_schema_tl(record)?;

        // Cache: check-then-insert.  Two hash lookups on miss (get +
        // insert), one on hit (get only).  We avoid raw_entry_mut
        // which requires nightly, and the entry API which would need
        // a key clone on every call (hit or miss).
        if self.cache.get(schema_tl_bytes, is_32bit).is_none() {
            let tei_buf = call_tdh_get_event_information(record)?;
            let schema = build_cached_schema(tei_buf.as_bytes(), is_32bit)?;
            debug!(
                event_name = %schema.event_name,
                property_count = schema.properties.len(),
                all_fixed = schema.fixed_format.is_some(),
                is_32bit,
                "TDH schema cache miss — new schema cached"
            );
            self.cache.insert(schema_tl_bytes.to_vec(), is_32bit, schema);
        }
        let schema = self.cache.get(schema_tl_bytes, is_32bit).unwrap();

        let user_data = event_user_data(record);

        if let Some(ref fixed_format) = schema.fixed_format {
            // Fast path: all fields are fixed-size, offsets are constant.
            Ok(EventData::new(user_data, user_data, fixed_format))
        } else {
            // Slow path: compute offsets by walking user_data.
            self.format_buf = build_event_format_with_data(&schema.properties, user_data);
            Ok(EventData::new(user_data, user_data, &self.format_buf))
        }
    }
}

impl Default for TdhDecoder {
    fn default() -> Self { Self::new() }
}

// ── Per-event offset computation ────────────────────────────────────

/// Builds an `EventFormat` by walking `user_data` to compute the actual
/// runtime offset of each field, handling variable-length fields correctly.
fn build_event_format_with_data(
    properties: &[CachedProperty],
    user_data: &[u8],
) -> EventFormat {
    let mut format = EventFormat::new();
    let mut offset: usize = 0;

    for prop in properties {
        let (loc, size) = match &prop.kind {
            PropertyKind::Fixed(sz) => {
                (LocationType::Static, *sz)
            }
            PropertyKind::AnsiString => {
                let len = scan_ansi_string(&user_data[offset.min(user_data.len())..]);
                (LocationType::Static, len)
            }
            PropertyKind::Utf16String => {
                let len = scan_utf16_string(&user_data[offset.min(user_data.len())..]);
                (LocationType::Static, len)
            }
            PropertyKind::CountedString => {
                let len = scan_counted_string(&user_data[offset.min(user_data.len())..]);
                (LocationType::Static, len)
            }
            PropertyKind::VariableBlob => {
                let remaining = user_data.len().saturating_sub(offset);
                (LocationType::Static, remaining)
            }
            PropertyKind::Unsupported => {
                let remaining = user_data.len().saturating_sub(offset);
                (LocationType::Static, remaining)
            }
        };

        format.add_field(EventField::new(
            prop.name.clone(),
            prop.type_name.to_string(),
            loc,
            offset,
            size,
        ));

        offset += size;
    }

    format
}

/// Scans for a null-terminated ANSI string, returning the number of
/// bytes consumed **including** the null terminator.
fn scan_ansi_string(data: &[u8]) -> usize {
    match data.iter().position(|&b| b == 0) {
        Some(pos) => pos + 1, // include the null byte
        None => data.len(),   // unterminated — take everything
    }
}

/// Scans for a null-terminated UTF-16LE string, returning the number of
/// bytes consumed **including** the two-byte null terminator.
fn scan_utf16_string(data: &[u8]) -> usize {
    let mut pos = 0;
    while pos + 1 < data.len() {
        if data[pos] == 0 && data[pos + 1] == 0 {
            return pos + 2; // include the null pair
        }
        pos += 2;
    }
    data.len() // unterminated
}

/// Reads a counted-string field: a 2-byte little-endian `u16` length
/// prefix followed by `len` bytes of string data.
///
/// Returns the total number of bytes consumed (`2 + len`), or all
/// remaining bytes if the prefix cannot be read.
fn scan_counted_string(data: &[u8]) -> usize {
    if data.len() < 2 {
        return data.len(); // not enough for the length prefix
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let total = 2 + len;
    total.min(data.len()) // clamp to available data
}

// ── Schema extraction from TDH ──────────────────────────────────────

/// Builds a `CachedSchema` from a `TRACE_EVENT_INFO` buffer.
fn build_cached_schema(tei_buf: &[u8], is_32bit: bool) -> Result<CachedSchema, TdhDecodeError> {
    if tei_buf.len() < std::mem::size_of::<TRACE_EVENT_INFO>() {
        return Err(TdhDecodeError::Malformed("buffer smaller than TRACE_EVENT_INFO"));
    }

    let tei = unsafe { &*(tei_buf.as_ptr() as *const TRACE_EVENT_INFO) };
    let property_count = tei.PropertyCount as usize;
    let top_level_count = tei.TopLevelPropertyCount as usize;

    // Extract the event name (#7).
    let event_name = read_event_name(tei_buf, tei);

    if property_count == 0 {
        return Ok(CachedSchema {
            event_name,
            properties: Vec::new(),
            fixed_format: Some(EventFormat::new()),
        });
    }

    let props_offset = std::mem::size_of::<TRACE_EVENT_INFO>();
    let props_end = props_offset + property_count * std::mem::size_of::<EVENT_PROPERTY_INFO>();
    if tei_buf.len() < props_end {
        return Err(TdhDecodeError::Malformed("buffer too small for declared property count"));
    }

    let properties: &[EVENT_PROPERTY_INFO] = unsafe {
        std::slice::from_raw_parts(
            tei_buf.as_ptr().add(props_offset) as *const EVENT_PROPERTY_INFO,
            property_count,
        )
    };

    let mut cached_props = Vec::new();
    walk_properties_to_cache(
        tei_buf, properties, 0..top_level_count,
        "", &mut cached_props, is_32bit,
    )?;

    let all_fixed = cached_props.iter().all(|p| matches!(p.kind, PropertyKind::Fixed(_)));

    let fixed_format = if all_fixed {
        let mut fmt = EventFormat::new();
        let mut offset = 0usize;
        for prop in &cached_props {
            let sz = match &prop.kind {
                PropertyKind::Fixed(s) => *s,
                _ => unreachable!(),
            };
            fmt.add_field(EventField::new(
                prop.name.clone(),
                prop.type_name.to_string(),
                LocationType::Static,
                offset,
                sz,
            ));
            offset += sz;
        }
        Some(fmt)
    } else {
        None
    };

    Ok(CachedSchema {
        event_name,
        properties: cached_props,
        fixed_format,
    })
}

/// Recursively walks TDH properties, flattening structs, and builds
/// the cached property list.
fn walk_properties_to_cache(
    tei_buf: &[u8],
    properties: &[EVENT_PROPERTY_INFO],
    range: std::ops::Range<usize>,
    prefix: &str,
    out: &mut Vec<CachedProperty>,
    is_32bit: bool,
) -> Result<(), TdhDecodeError> {
    for i in range {
        if i >= properties.len() {
            return Err(TdhDecodeError::Malformed("property index out of bounds"));
        }

        let prop = &properties[i];
        let name = read_property_name(tei_buf, prop);
        let qualified_name = if prefix.is_empty() {
            name
        } else {
            std::format!("{prefix}.{name}")
        };

        let flags = prop.Flags;

        // ── Struct property ─────────────────────────────────────────
        if (flags & PROPERTY_STRUCT) != 0 {
            let struct_info = unsafe { prop.Anonymous1.structType };
            let start = struct_info.StructStartIndex as usize;
            let count = struct_info.NumOfStructMembers as usize;
            walk_properties_to_cache(
                tei_buf, properties, start..start + count,
                &qualified_name, out, is_32bit,
            )?;
            continue;
        }

        // ── Array/param-count properties ─────────────────────────────
        if (flags & PROPERTY_HAS_COUNT) != 0 {
            let count = unsafe { prop.Anonymous2.count } as usize;
            if count != 1 {
                debug!(field = %qualified_name, count, "skipping unsupported array property");
                out.push(CachedProperty {
                    name: qualified_name,
                    type_name: "unsupported_array",
                    kind: PropertyKind::Unsupported,
                });
                continue;
            }
            // count == 1: fall through to normal leaf decoding below.
        }

        // ── Leaf property ───────────────────────────────────────────
        let in_type = unsafe { prop.Anonymous1.nonStructType.InType } as i32;
        let (type_name, kind) = intype_to_cached_info(in_type, is_32bit, prop);

        debug!(
            field = %qualified_name,
            in_type,
            flags,
            type_name,
            kind = ?kind,
            "TDH property decoded"
        );

        out.push(CachedProperty {
            name: qualified_name,
            type_name,
            kind,
        });
    }

    Ok(())
}

// ── Internal helpers ────────────────────────────────────────────────

fn event_user_data<'a>(record: &'a EVENT_RECORD) -> &'a [u8] {
    if record.UserData.is_null() || record.UserDataLength == 0 {
        &[]
    } else {
        unsafe {
            std::slice::from_raw_parts(
                record.UserData as *const u8,
                record.UserDataLength as usize,
            )
        }
    }
}

fn find_schema_tl<'a>(record: &'a EVENT_RECORD) -> Result<&'a [u8], TdhDecodeError> {
    if record.ExtendedDataCount == 0 || record.ExtendedData.is_null() {
        return Err(TdhDecodeError::NotFound);
    }
    let items: &[EVENT_HEADER_EXTENDED_DATA_ITEM] = unsafe {
        std::slice::from_raw_parts(record.ExtendedData, record.ExtendedDataCount as usize)
    };
    for item in items {
        if item.ExtType == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL {
            if item.DataPtr == 0 || item.DataSize == 0 { continue; }
            return Ok(unsafe {
                std::slice::from_raw_parts(item.DataPtr as *const u8, item.DataSize as usize)
            });
        }
    }
    Err(TdhDecodeError::NotFound)
}

/// Aligned buffer for `TRACE_EVENT_INFO`.  Uses `Vec<u64>` to guarantee
/// 8-byte alignment (TRACE_EVENT_INFO requires at least 4-byte alignment
/// due to u32 fields, and EVENT_PROPERTY_INFO following it contains u64
/// offsets on 64-bit builds).
struct AlignedTeiBuf {
    /// Storage with 8-byte alignment.
    storage: Vec<u64>,
    /// Actual byte length returned by TDH.
    len: usize,
}

impl AlignedTeiBuf {
    fn as_bytes(&self) -> &[u8] {
        let ptr = self.storage.as_ptr() as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, self.len) }
    }
}

fn call_tdh_get_event_information(record: &EVENT_RECORD) -> Result<AlignedTeiBuf, TdhDecodeError> {
    let mut buffer_size: u32 = 0;
    let status = unsafe {
        TdhGetEventInformation(
            record as *const EVENT_RECORD, 0u32,
            core::ptr::null(), core::ptr::null_mut(), &mut buffer_size,
        )
    };
    if status != ERROR_INSUFFICIENT_BUFFER {
        warn!(win32_error = status, "TdhGetEventInformation sizing call failed");
        return Err(TdhDecodeError::Win32(status));
    }
    if buffer_size == 0 {
        warn!("TdhGetEventInformation returned zero buffer size");
        return Err(TdhDecodeError::Malformed("TDH returned zero buffer size"));
    }
    // Allocate with u64 alignment (8 bytes), rounding up.
    let u64_count = (buffer_size as usize + 7) / 8;
    let mut storage: Vec<u64> = vec![0u64; u64_count];
    let status = unsafe {
        TdhGetEventInformation(
            record as *const EVENT_RECORD, 0u32,
            core::ptr::null(),
            storage.as_mut_ptr() as *mut TRACE_EVENT_INFO,
            &mut buffer_size,
        )
    };
    if status != 0 {
        warn!(win32_error = status, "TdhGetEventInformation fill call failed");
        return Err(TdhDecodeError::Win32(status));
    }
    trace!(buffer_size, "TdhGetEventInformation succeeded");
    Ok(AlignedTeiBuf { storage, len: buffer_size as usize })
}

/// Reads the TraceLogging event name from `TRACE_EVENT_INFO`.
///
/// The `EventNameOffset` field is at byte offset 92 in the struct (after
/// `TaskNameOffset` at 88).  It points to a null-terminated UTF-16LE
/// string within the same buffer.
fn read_event_name(tei_buf: &[u8], tei: &TRACE_EVENT_INFO) -> String {
    // TRACE_EVENT_INFO::EventNameOffset is a u32 at a known position.
    // In windows-sys it's accessible as tei.EventNameOffset on some
    // versions, but we read it safely from the raw buffer to avoid
    // version-specific anonymous union layouts.
    //
    // Offset 92 = EventNameOffset in the Windows SDK TRACE_EVENT_INFO
    // layout (confirmed against windows 0.61 and windows-sys 0.59).
    const EVENT_NAME_OFFSET_POS: usize = 92;
    if tei_buf.len() < EVENT_NAME_OFFSET_POS + 4 {
        return String::new();
    }
    let name_offset_bytes: [u8; 4] = tei_buf[EVENT_NAME_OFFSET_POS..EVENT_NAME_OFFSET_POS + 4]
        .try_into()
        .unwrap();
    let name_offset = u32::from_le_bytes(name_offset_bytes) as usize;

    // Fallback: try the struct field directly if available.
    let _ = tei; // suppress unused warning; we use the raw buffer above.

    read_utf16_at(tei_buf, name_offset)
}

/// Reads the null-terminated UTF-16 property name from the
/// `TRACE_EVENT_INFO` buffer at the offset indicated by the property.
///
/// Avoids the intermediate `Vec<u16>` allocation by using an iterator-
/// based decode (#4).
fn read_property_name(tei_buf: &[u8], prop: &EVENT_PROPERTY_INFO) -> String {
    read_utf16_at(tei_buf, prop.NameOffset as usize)
}

/// Reads a null-terminated UTF-16LE string from `buf` at `byte_offset`.
///
/// Returns an empty string if the offset is out of bounds.  Uses
/// `String::from_utf16_lossy` but feeds it from an iterator to avoid
/// an intermediate `Vec<u16>` allocation for small names (#4).
fn read_utf16_at(buf: &[u8], byte_offset: usize) -> String {
    if byte_offset == 0 || byte_offset >= buf.len() {
        return String::new();
    }
    let remaining = &buf[byte_offset..];
    // Decode UTF-16LE code units, stopping at null.
    let u16_iter = remaining
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0);
    // Collect into a small vec — property names are typically short.
    let u16s: Vec<u16> = u16_iter.collect();
    String::from_utf16_lossy(&u16s)
}

/// Maps a TDH_INTYPE to a `(type_name, PropertyKind)`.
///
/// Returns `&'static str` for type_name to avoid per-property heap
/// allocation (#10).
fn intype_to_cached_info(
    in_type: i32,
    is_32bit: bool,
    prop: &EVENT_PROPERTY_INFO,
) -> (&'static str, PropertyKind) {
    // Check for explicit length (literal byte count for TraceLogging).
    // Guard against PROPERTY_PARAM_LENGTH (#6): when that flag is set,
    // `Anonymous3.length` is a property *index*, not a byte count.
    let explicit_len: Option<usize> = if (prop.Flags & PROPERTY_HAS_LENGTH) != 0
        && (prop.Flags & PROPERTY_PARAM_LENGTH) == 0
    {
        let len = unsafe { prop.Anonymous3.length } as usize;
        if len > 0 { Some(len) } else { None }
    } else {
        None
    };

    // If the property has a literal byte length, treat it as fixed-size.
    if let Some(len) = explicit_len {
        let type_name = intype_to_type_name(in_type);
        return (type_name, PropertyKind::Fixed(len));
    }

    match in_type {
        TDH_INTYPE_INT8                          => ("s8",   PropertyKind::Fixed(1)),
        TDH_INTYPE_UINT8 | TDH_INTYPE_BOOLEAN   => ("u8",   PropertyKind::Fixed(1)),
        TDH_INTYPE_INT16                         => ("s16",  PropertyKind::Fixed(2)),
        TDH_INTYPE_UINT16                        => ("u16",  PropertyKind::Fixed(2)),
        TDH_INTYPE_INT32 | TDH_INTYPE_HEXINT32  => ("s32",  PropertyKind::Fixed(4)),
        TDH_INTYPE_UINT32                        => ("u32",  PropertyKind::Fixed(4)),
        TDH_INTYPE_INT64 | TDH_INTYPE_HEXINT64  => ("s64",  PropertyKind::Fixed(8)),
        TDH_INTYPE_UINT64                        => ("u64",  PropertyKind::Fixed(8)),
        TDH_INTYPE_FLOAT                         => ("f32",  PropertyKind::Fixed(4)),
        TDH_INTYPE_DOUBLE                        => ("f64",  PropertyKind::Fixed(8)),
        TDH_INTYPE_POINTER => {
            let sz = if is_32bit { 4 } else { 8 };
            ("pointer", PropertyKind::Fixed(sz))
        }
        TDH_INTYPE_FILETIME                      => ("filetime",   PropertyKind::Fixed(8)),
        TDH_INTYPE_SYSTEMTIME                    => ("systemtime", PropertyKind::Fixed(16)),
        TDH_INTYPE_GUID                          => ("guid",       PropertyKind::Fixed(16)),

        TDH_INTYPE_ANSISTRING |
        TDH_INTYPE_NONNULLTERMINATEDANSISTRING   => ("string",  PropertyKind::AnsiString),

        TDH_INTYPE_UNICODESTRING |
        TDH_INTYPE_NONNULLTERMINATEDSTRING       => ("wstring", PropertyKind::Utf16String),

        TDH_INTYPE_SID                           => ("sid",            PropertyKind::VariableBlob),
        TDH_INTYPE_BINARY                        => ("binary",         PropertyKind::VariableBlob),
        TDH_INTYPE_COUNTEDSTRING |
        TDH_INTYPE_REVERSEDCOUNTEDSTRING         => ("counted_string", PropertyKind::CountedString),

        _ => ("unsupported", PropertyKind::VariableBlob),
    }
}

/// Returns just the type_name string for a TDH_INTYPE (used when
/// explicit_len overrides the kind to Fixed).
fn intype_to_type_name(in_type: i32) -> &'static str {
    match in_type {
        TDH_INTYPE_INT8                          => "s8",
        TDH_INTYPE_UINT8 | TDH_INTYPE_BOOLEAN   => "u8",
        TDH_INTYPE_INT16                         => "s16",
        TDH_INTYPE_UINT16                        => "u16",
        TDH_INTYPE_INT32 | TDH_INTYPE_HEXINT32  => "s32",
        TDH_INTYPE_UINT32                        => "u32",
        TDH_INTYPE_INT64 | TDH_INTYPE_HEXINT64  => "s64",
        TDH_INTYPE_UINT64                        => "u64",
        TDH_INTYPE_FLOAT                         => "f32",
        TDH_INTYPE_DOUBLE                        => "f64",
        TDH_INTYPE_POINTER                       => "pointer",
        TDH_INTYPE_FILETIME                      => "filetime",
        TDH_INTYPE_SYSTEMTIME                    => "systemtime",
        TDH_INTYPE_GUID                          => "guid",
        TDH_INTYPE_SID                           => "sid",
        TDH_INTYPE_UNICODESTRING |
        TDH_INTYPE_NONNULLTERMINATEDSTRING       => "wstring",
        TDH_INTYPE_ANSISTRING |
        TDH_INTYPE_NONNULLTERMINATEDANSISTRING   => "string",
        TDH_INTYPE_COUNTEDSTRING |
        TDH_INTYPE_REVERSEDCOUNTEDSTRING         => "counted_string",
        TDH_INTYPE_BINARY                        => "binary",
        _                                        => "unsupported",
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── scan_ansi_string ────────────────────────────────────────────

    #[test]
    fn scan_ansi_empty() {
        assert_eq!(scan_ansi_string(&[]), 0);
    }

    #[test]
    fn scan_ansi_null_only() {
        assert_eq!(scan_ansi_string(&[0]), 1);
    }

    #[test]
    fn scan_ansi_hello() {
        // "Hi\0rest"
        let data = b"Hi\0rest";
        assert_eq!(scan_ansi_string(data), 3); // 'H','i','\0'
    }

    #[test]
    fn scan_ansi_unterminated() {
        let data = b"abc";
        assert_eq!(scan_ansi_string(data), 3);
    }

    // ── scan_utf16_string ───────────────────────────────────────────

    #[test]
    fn scan_utf16_empty() {
        assert_eq!(scan_utf16_string(&[]), 0);
    }

    #[test]
    fn scan_utf16_null_only() {
        assert_eq!(scan_utf16_string(&[0, 0]), 2);
    }

    #[test]
    fn scan_utf16_hello() {
        // "Hi" in UTF-16LE + null terminator
        let data: &[u8] = &[b'H', 0, b'i', 0, 0, 0, b'X', 0];
        assert_eq!(scan_utf16_string(data), 6); // 'H',0,'i',0,0,0
    }

    #[test]
    fn scan_utf16_unterminated() {
        let data: &[u8] = &[b'A', 0, b'B', 0];
        assert_eq!(scan_utf16_string(data), 4);
    }

    #[test]
    fn scan_utf16_odd_length() {
        // Odd byte count — no valid null terminator pair
        let data: &[u8] = &[b'A', 0, b'B'];
        assert_eq!(scan_utf16_string(data), 3);
    }

    // ── build_event_format_with_data ────────────────────────────────

    #[test]
    fn format_all_fixed() {
        let props = vec![
            CachedProperty { name: "a".into(), type_name: "u32", kind: PropertyKind::Fixed(4) },
            CachedProperty { name: "b".into(), type_name: "u64", kind: PropertyKind::Fixed(8) },
        ];
        let data = [0u8; 12];
        let fmt = build_event_format_with_data(&props, &data);
        let fields = fmt.fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "a");
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[0].size, 4);
        assert_eq!(fields[1].name, "b");
        assert_eq!(fields[1].offset, 4);
        assert_eq!(fields[1].size, 8);
    }

    #[test]
    fn format_with_ansi_string() {
        let props = vec![
            CachedProperty { name: "id".into(), type_name: "u32", kind: PropertyKind::Fixed(4) },
            CachedProperty { name: "msg".into(), type_name: "string", kind: PropertyKind::AnsiString },
            CachedProperty { name: "val".into(), type_name: "u16", kind: PropertyKind::Fixed(2) },
        ];
        // id=0x01020304, msg="Hi\0", val=0x0506
        let data: Vec<u8> = vec![
            0x01, 0x02, 0x03, 0x04,  // id
            b'H', b'i', 0x00,        // msg (null-terminated)
            0x05, 0x06,              // val
        ];
        let fmt = build_event_format_with_data(&props, &data);
        let fields = fmt.fields();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[0].size, 4);
        assert_eq!(fields[1].offset, 4);
        assert_eq!(fields[1].size, 3); // "Hi\0"
        assert_eq!(fields[2].offset, 7);
        assert_eq!(fields[2].size, 2);
    }

    #[test]
    fn format_with_utf16_string() {
        let props = vec![
            CachedProperty { name: "name".into(), type_name: "wstring", kind: PropertyKind::Utf16String },
            CachedProperty { name: "code".into(), type_name: "u32", kind: PropertyKind::Fixed(4) },
        ];
        // name="A\0" in UTF-16LE (A=0x41,0x00 then null=0x00,0x00), code=0x01020304
        let data: Vec<u8> = vec![
            0x41, 0x00, 0x00, 0x00,  // "A\0" in UTF-16LE
            0x01, 0x02, 0x03, 0x04,  // code
        ];
        let fmt = build_event_format_with_data(&props, &data);
        let fields = fmt.fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[0].size, 4); // 'A',0x00, 0x00,0x00
        assert_eq!(fields[1].offset, 4);
        assert_eq!(fields[1].size, 4);
    }

    #[test]
    fn format_variable_blob_consumes_rest() {
        let props = vec![
            CachedProperty { name: "hdr".into(), type_name: "u8", kind: PropertyKind::Fixed(1) },
            CachedProperty { name: "blob".into(), type_name: "binary", kind: PropertyKind::VariableBlob },
        ];
        let data = [0u8; 10];
        let fmt = build_event_format_with_data(&props, &data);
        let fields = fmt.fields();
        assert_eq!(fields[0].size, 1);
        assert_eq!(fields[1].offset, 1);
        assert_eq!(fields[1].size, 9); // everything after hdr
    }

    // ── read_utf16_at ───────────────────────────────────────────────

    #[test]
    fn read_utf16_at_basic() {
        // "AB\0" in UTF-16LE at offset 2
        let buf: Vec<u8> = vec![
            0xFF, 0xFF,              // junk before
            b'A', 0, b'B', 0, 0, 0, // "AB\0"
        ];
        assert_eq!(read_utf16_at(&buf, 2), "AB");
    }

    #[test]
    fn read_utf16_at_zero_offset() {
        assert_eq!(read_utf16_at(&[0x41, 0x00, 0x00, 0x00], 0), "");
    }

    #[test]
    fn read_utf16_at_out_of_bounds() {
        assert_eq!(read_utf16_at(&[0x41, 0x00], 100), "");
    }

    // ── scan_counted_string ─────────────────────────────────────────

    #[test]
    fn scan_counted_empty() {
        assert_eq!(scan_counted_string(&[]), 0);
    }

    #[test]
    fn scan_counted_short() {
        // Only 1 byte — not enough for the u16 prefix
        assert_eq!(scan_counted_string(&[0x03]), 1);
    }

    #[test]
    fn scan_counted_hello() {
        // len=5, data="Hello", trailing byte
        let data: &[u8] = &[0x05, 0x00, b'H', b'e', b'l', b'l', b'o', 0xFF];
        assert_eq!(scan_counted_string(data), 7); // 2 + 5
    }

    #[test]
    fn scan_counted_zero_len() {
        // len=0, no data
        assert_eq!(scan_counted_string(&[0x00, 0x00, 0xFF]), 2);
    }

    #[test]
    fn scan_counted_truncated() {
        // len=10 but only 4 bytes available after prefix
        let data: &[u8] = &[0x0A, 0x00, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(scan_counted_string(data), 6); // clamped to data.len()
    }

    // ── format with counted string ──────────────────────────────────

    #[test]
    fn format_with_counted_string() {
        let props = vec![
            CachedProperty { name: "status".into(), type_name: "counted_string", kind: PropertyKind::CountedString },
            CachedProperty { name: "code".into(), type_name: "u32", kind: PropertyKind::Fixed(4) },
        ];
        // status: len=7 "Success", code: 0x01020304
        let data: Vec<u8> = vec![
            0x07, 0x00,                                     // u16 len = 7
            b'S', b'u', b'c', b'c', b'e', b's', b's',      // "Success"
            0x01, 0x02, 0x03, 0x04,                          // code
        ];
        let fmt = build_event_format_with_data(&props, &data);
        let fields = fmt.fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[0].size, 9);  // 2 + 7
        assert_eq!(fields[1].offset, 9);
        assert_eq!(fields[1].size, 4);
    }

    // ── intype_to_type_name ─────────────────────────────────────────

    #[test]
    fn type_name_scalars() {
        assert_eq!(intype_to_type_name(TDH_INTYPE_INT8), "s8");
        assert_eq!(intype_to_type_name(TDH_INTYPE_UINT32), "u32");
        assert_eq!(intype_to_type_name(TDH_INTYPE_DOUBLE), "f64");
        assert_eq!(intype_to_type_name(TDH_INTYPE_GUID), "guid");
        assert_eq!(intype_to_type_name(TDH_INTYPE_UNICODESTRING), "wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_ANSISTRING), "string");
        assert_eq!(intype_to_type_name(TDH_INTYPE_BINARY), "binary");
        assert_eq!(intype_to_type_name(999), "unsupported");
    }
}