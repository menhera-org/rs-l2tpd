//! The uncompressed ar/ustar subset documented by deb(5).
use std::io;

pub struct Entry<'a> {
    pub name: &'a str,
    pub mode: u32,
    pub directory: bool,
    pub data: &'a [u8],
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid package archive")
}

fn octal(field: &mut [u8], value: u64) -> io::Result<()> {
    let text = format!("{:0width$o}\0", value, width = field.len() - 1);
    if text.len() != field.len() {
        return Err(invalid());
    }
    field.copy_from_slice(text.as_bytes());
    Ok(())
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && name.split('/').all(|part| part != ".." && part != ".")
        && !name.bytes().any(|b| b == 0 || b.is_ascii_control())
}

pub fn tar(entries: &[Entry<'_>]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for entry in entries {
        if !safe_name(entry.name)
            || entry.name.len() > 100
            || (entry.directory && !entry.data.is_empty())
        {
            return Err(invalid());
        }
        let mut header = [0u8; 512];
        header[..entry.name.len()].copy_from_slice(entry.name.as_bytes());
        octal(&mut header[100..108], entry.mode.into())?;
        octal(&mut header[108..116], 0)?;
        octal(&mut header[116..124], 0)?;
        octal(&mut header[124..136], entry.data.len() as u64)?;
        octal(&mut header[136..148], 0)?;
        header[148..156].fill(b' ');
        header[156] = if entry.directory { b'5' } else { b'0' };
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[265..269].copy_from_slice(b"root");
        header[297..301].copy_from_slice(b"root");
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(entry.data);
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out.resize(out.len() + 1024, 0);
    Ok(out)
}

pub fn deb(control: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    for (name, bytes) in [
        ("debian-binary", &b"2.0\n"[..]),
        ("control.tar", control),
        ("data.tar", data),
    ] {
        let header = format!(
            "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}\x60\n",
            0,
            0,
            0,
            "100644",
            bytes.len()
        );
        assert_eq!(header.len(), 60);
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(bytes);
        if bytes.len() % 2 != 0 {
            out.push(b'\n');
        }
    }
    out
}

fn number(bytes: &[u8], radix: u32) -> io::Result<usize> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid())?
        .trim_matches([' ', '\0']);
    usize::from_str_radix(text, radix).map_err(|_| invalid())
}

fn take<'a>(input: &mut &'a [u8], size: usize) -> io::Result<&'a [u8]> {
    let (part, rest) = input.split_at_checked(size).ok_or_else(invalid)?;
    *input = rest;
    Ok(part)
}

fn member<'a>(input: &mut &'a [u8], name: &str) -> io::Result<&'a [u8]> {
    let header = take(input, 60)?;
    let actual = std::str::from_utf8(&header[..16])
        .map_err(|_| invalid())?
        .trim_end()
        .trim_end_matches('/');
    if actual != name || &header[58..] != b"\x60\n" {
        return Err(invalid());
    }
    let size = number(&header[48..58], 10)?;
    let data = take(input, size)?;
    if size % 2 != 0 && take(input, 1)? != b"\n" {
        return Err(invalid());
    }
    Ok(data)
}

/// Lists our uncompressed packages; never extracts paths or executes scripts.
pub fn list(mut input: &[u8]) -> io::Result<String> {
    if take(&mut input, 8)? != b"!<arch>\n" || member(&mut input, "debian-binary")? != b"2.0\n" {
        return Err(invalid());
    }
    let control = member(&mut input, "control.tar")?;
    let data = member(&mut input, "data.tar")?;
    if !input.is_empty() {
        return Err(invalid());
    }
    let mut out = String::new();
    for (label, bytes) in [("control.tar", control), ("data.tar", data)] {
        out.push_str(label);
        out.push('\n');
        list_tar(bytes, &mut out)?;
    }
    Ok(out)
}

fn list_tar(mut input: &[u8], out: &mut String) -> io::Result<()> {
    loop {
        let header = take(&mut input, 512)?;
        if header == [0; 512] {
            if take(&mut input, 512)? != [0; 512] || input.iter().any(|&b| b != 0) {
                return Err(invalid());
            }
            return Ok(());
        }
        let sum: usize = header
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    usize::from(b)
                }
            })
            .sum();
        if number(&header[148..156], 8)? != sum || &header[257..265] != b"ustar\x0000" {
            return Err(invalid());
        }
        let name = header[..100]
            .split(|&b| b == 0)
            .next()
            .ok_or_else(invalid)?;
        let name = std::str::from_utf8(name).map_err(|_| invalid())?;
        if !safe_name(name) || !matches!(header[156], b'0' | b'5') {
            return Err(invalid());
        }
        let size = number(&header[124..136], 8)?;
        if header[156] == b'5' && size != 0 {
            return Err(invalid());
        }
        let mode = number(&header[100..108], 8)?;
        let uid = number(&header[108..116], 8)?;
        let gid = number(&header[116..124], 8)?;
        out.push_str(&format!("{mode:04o} {uid}:{gid} {size} {name}\n"));
        take(&mut input, size)?;
        let pad = (512 - size % 512) % 512;
        if take(&mut input, pad)?.iter().any(|&b| b != 0) {
            return Err(invalid());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let entries = [
            Entry {
                name: "etc/",
                mode: 0o755,
                directory: true,
                data: b"",
            },
            Entry {
                name: "etc/example",
                mode: 0o644,
                directory: false,
                data: b"odd",
            },
        ];
        deb(&tar(&[]).unwrap(), &tar(&entries).unwrap())
    }

    #[test]
    fn fixed_tree_is_deterministic_and_has_root_modes() {
        let bytes = fixture();
        assert_eq!(bytes, fixture());
        let text = list(&bytes).unwrap();
        assert!(text.contains("0755 0:0 0 etc/"));
        assert!(text.contains("0644 0:0 3 etc/example"));
    }

    #[test]
    fn every_truncation_and_corrupt_checksum_is_rejected() {
        let bytes = fixture();
        for end in 0..bytes.len() {
            assert!(list(&bytes[..end]).is_err(), "accepted truncation {end}");
        }
        let mut broken = bytes.clone();
        let at = broken
            .windows(11)
            .position(|w| w == b"etc/example")
            .unwrap();
        broken[at] ^= 1;
        assert!(list(&broken).is_err());
        assert!(list(b"not a deb").is_err());
    }

    #[test]
    fn unsafe_or_unrepresentable_names_are_rejected() {
        for name in [
            "",
            "/etc/passwd",
            "../escape",
            "a/../b",
            "./a",
            "a\nb",
            &"x".repeat(101),
        ] {
            assert!(
                tar(&[Entry {
                    name,
                    mode: 0o644,
                    directory: false,
                    data: b""
                }])
                .is_err()
            );
        }
        assert!(
            tar(&[Entry {
                name: "etc/",
                mode: 0o755,
                directory: true,
                data: b"bad"
            }])
            .is_err()
        );
    }
}
