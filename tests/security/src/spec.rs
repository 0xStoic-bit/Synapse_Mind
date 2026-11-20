//! Denetçi -> hedef paket tarifi (ikili biçim). Hedef süreç sırları kendi üretmez; dosyadan
//! okur ve doğrudan `RawCapturePacket` alanlarına kopyalar (tek kopya), okuma tamponunu zeroize eder.
//! Böylece hedefin belleğindeki tek sır kopyaları gerçek boru hattının (paket -> guard) kopyalarıdır.

use s_types::{ClipboardFormat, EventKind, RawCapturePacket, RawPayload};
use std::io;

pub const KIND_ACCESSIBILITY: u8 = 0;
pub const KIND_CLIPBOARD: u8 = 1;
pub const KIND_FRAME: u8 = 2;
pub const KIND_CLIPBOARD_IGNORED: u8 = 3;

const MAGIC: &[u8; 4] = b"G2SP";

#[derive(Debug, Clone)]
pub struct PacketSpec {
    pub kind: u8,
    pub process_name: String,
    pub title: String,
    pub text: String,
}

pub fn encode(specs: &[PacketSpec]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(specs.len() as u32).to_le_bytes());
    for s in specs {
        out.push(s.kind);
        for f in [&s.process_name, &s.title, &s.text] {
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f.as_bytes());
        }
    }
    out
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> io::Result<&'a [u8]> {
    let end = pos
        .checked_add(n)
        .filter(|&e| e <= buf.len())
        .ok_or_else(|| bad("truncated spec"))?;
    let s = &buf[*pos..end];
    *pos = end;
    Ok(s)
}

fn take_string(buf: &[u8], pos: &mut usize) -> io::Result<String> {
    let n = u32::from_le_bytes(take(buf, pos, 4)?.try_into().unwrap()) as usize;
    // Tek kopya: doğrudan paketin sahip olacağı String tamponu.
    String::from_utf8(take(buf, pos, n)?.to_vec()).map_err(|_| bad("utf8"))
}

/// Tarifi doğrudan `RawCapturePacket`'lara çevirir (başka ara kopya bırakmaz).
pub fn decode_to_packets(buf: &[u8]) -> io::Result<Vec<RawCapturePacket>> {
    let mut pos = 0usize;
    if take(buf, &mut pos, 4)? != MAGIC {
        return Err(bad("magic"));
    }
    let count = u32::from_le_bytes(take(buf, &mut pos, 4)?.try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let kind = take(buf, &mut pos, 1)?[0];
        let process_name = take_string(buf, &mut pos)?;
        let window_title = take_string(buf, &mut pos)?;
        let text = take_string(buf, &mut pos)?;
        let (event_kind, raw_payload) = match kind {
            KIND_ACCESSIBILITY => (
                EventKind::AccessibilityTreeChanged { node_count: 1 },
                RawPayload::AccessibilityText(text),
            ),
            KIND_CLIPBOARD => (
                EventKind::ClipboardCopied {
                    format: ClipboardFormat::PlainText,
                },
                RawPayload::ClipboardText(text),
            ),
            KIND_CLIPBOARD_IGNORED => (
                EventKind::ClipboardCopied {
                    format: ClipboardFormat::IgnoredFormat,
                },
                RawPayload::ClipboardText(text),
            ),
            KIND_FRAME => (
                EventKind::VisualDifferenceDetected { phash_distance: 9 },
                RawPayload::ScreenFrame {
                    width: 4,
                    height: 4,
                    pixels_rgba: vec![0x7F; 64],
                },
            ),
            _ => return Err(bad("kind")),
        };
        out.push(RawCapturePacket {
            timestamp_ms: 1_763_424_000_000 + i as u64,
            process_id: 4242,
            process_name,
            window_title,
            event_kind,
            raw_payload,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let specs = vec![
            PacketSpec {
                kind: KIND_ACCESSIBILITY,
                process_name: "a.exe".into(),
                title: "t".into(),
                text: "hello".into(),
            },
            PacketSpec {
                kind: KIND_FRAME,
                process_name: "b.exe".into(),
                title: "tt".into(),
                text: String::new(),
            },
        ];
        let pk = decode_to_packets(&encode(&specs)).unwrap();
        assert_eq!(pk.len(), 2);
        assert_eq!(pk[0].process_name, "a.exe");
        assert!(matches!(&pk[0].raw_payload, RawPayload::AccessibilityText(t) if t == "hello"));
    }

    #[test]
    fn truncated_is_error() {
        let mut b = encode(&[PacketSpec {
            kind: 0,
            process_name: "a".into(),
            title: "b".into(),
            text: "c".into(),
        }]);
        b.truncate(b.len() - 1);
        assert!(decode_to_packets(&b).is_err());
    }
}
