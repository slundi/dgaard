//! `--hex` output: dump raw response bytes in xxd-style two-column hex/ASCII.

use super::Rendered;

pub fn render(item: &Rendered<'_>) -> String {
    let mut out = String::new();
    out.push_str(&format!(";; wire dump ({} bytes)\n", item.wire.len()));
    for (offset, chunk) in item.wire.chunks(16).enumerate() {
        let byte_offset = offset * 16;
        // hex column
        let mut hex = String::with_capacity(48);
        for b in chunk {
            hex.push_str(&format!("{b:02x} "));
        }
        // Pad to 16 bytes worth of hex for alignment when the last row is short.
        while hex.len() < 48 {
            hex.push(' ');
        }

        // ascii column
        let mut ascii = String::with_capacity(16);
        for b in chunk {
            if b.is_ascii_graphic() || *b == b' ' {
                ascii.push(*b as char);
            } else {
                ascii.push('.');
            }
        }

        out.push_str(&format!("{byte_offset:08x}  {hex} |{ascii}|\n"));
    }
    if let Some(ms) = item.elapsed_ms {
        out.push_str(&format!(";; Query time: {ms} ms\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_dump_covers_all_bytes() {
        let wire: Vec<u8> = (0..20u8).collect();
        let item = Rendered {
            query: "test",
            response: &hickory_proto::op::Message::query(),
            wire: &wire,
            elapsed_ms: None,
            verdict: None,
        };
        let out = render(&item);
        // First row prints bytes 00 through 0f
        assert!(out.contains("00000000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"));
        // Second row prints 10 through 13 (four bytes)
        assert!(out.contains("00000010  10 11 12 13"));
        assert!(out.contains(";; wire dump (20 bytes)"));
    }

    #[test]
    fn ascii_column_shows_printable() {
        let wire = b"digaard\x00\xff".to_vec();
        let item = Rendered {
            query: "test",
            response: &hickory_proto::op::Message::query(),
            wire: &wire,
            elapsed_ms: None,
            verdict: None,
        };
        let out = render(&item);
        assert!(out.contains("|digaard..|"));
    }
}
