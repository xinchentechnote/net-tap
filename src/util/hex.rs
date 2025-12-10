pub fn to_hex_str_veiw(data: &[u8]) -> String {
    let mut out = String::new();
    let mut offset = 0;

    for chunk in data.chunks(16) {
        // Offset
        out.push_str(&format!("{:04x}:  ", offset));

        // Hex part
        for (i, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x}", b));
            if i != chunk.len() - 1 {
                out.push(' ');
            }
        }

        // Padding if less than 16 bytes
        if chunk.len() < 16 {
            let pad = (16 - chunk.len()) * 3;
            out.push_str(&" ".repeat(pad));
        }

        // ASCII part
        out.push_str("  |");
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            };
            out.push(c);
        }
        out.push('|');

        out.push('\n');
        offset += 16;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_string() {
        let data = b"hello";
        let s = to_hex_str_veiw(data);

        let expected = "\
0000:  68 65 6c 6c 6f                                   |hello|
";

        assert_eq!(s, expected);
    }
    #[test]
    fn test_hex_string_multi_line() {
        let data = b"0123456789abcdefhello";
        let s = to_hex_str_veiw(data);

        let expected = "\
0000:  30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66  |0123456789abcdef|
0010:  68 65 6c 6c 6f                                   |hello|
";

        assert_eq!(s, expected);
    }
}
