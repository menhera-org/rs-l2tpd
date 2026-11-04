//! Reject wrong-architecture and dynamically linked ELF64 input.
use std::io;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "expected a static target ELF64 executable",
    )
}

fn bytes<const N: usize>(input: &[u8], offset: usize) -> io::Result<[u8; N]> {
    input
        .get(offset..offset.checked_add(N).ok_or_else(invalid)?)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())
}

pub fn check(input: &[u8], machine: u16) -> io::Result<()> {
    if bytes::<7>(input, 0)? != *b"\x7fELF\x02\x01\x01"
        || !matches!(u16::from_le_bytes(bytes(input, 16)?), 2 | 3)
        || u16::from_le_bytes(bytes(input, 18)?) != machine
        || u16::from_le_bytes(bytes(input, 54)?) != 56
    {
        return Err(invalid());
    }
    let offset = usize::try_from(u64::from_le_bytes(bytes(input, 32)?)).map_err(|_| invalid())?;
    let count = usize::from(u16::from_le_bytes(bytes(input, 56)?));
    if count == 0 {
        return Err(invalid());
    }
    for index in 0..count {
        let header = bytes::<56>(input, offset.checked_add(index * 56).ok_or_else(invalid)?)?;
        let kind = u32::from_le_bytes(bytes(&header, 0)?);
        if kind == 3 {
            return Err(invalid());
        } // PT_INTERP
        let start =
            usize::try_from(u64::from_le_bytes(bytes(&header, 8)?)).map_err(|_| invalid())?;
        let size =
            usize::try_from(u64::from_le_bytes(bytes(&header, 32)?)).map_err(|_| invalid())?;
        let data = input
            .get(start..start.checked_add(size).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if kind == 2 {
            // PT_DYNAMIC
            let (entries, rest) = data.as_chunks::<16>();
            if !rest.is_empty() {
                return Err(invalid());
            }
            let mut terminated = false;
            for entry in entries {
                match u64::from_le_bytes(bytes(entry, 0)?) {
                    0 => {
                        terminated = true;
                        break;
                    }
                    1 => return Err(invalid()), // DT_NEEDED
                    _ => {}
                }
            }
            if !terminated {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut out = vec![0; 120];
        out[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        out[16..18].copy_from_slice(&2u16.to_le_bytes());
        out[18..20].copy_from_slice(&62u16.to_le_bytes());
        out[32..40].copy_from_slice(&64u64.to_le_bytes());
        out[54..56].copy_from_slice(&56u16.to_le_bytes());
        out[56..58].copy_from_slice(&1u16.to_le_bytes());
        out
    }

    #[test]
    fn rejects_interpreters_wrong_architecture_and_truncated_headers() {
        let mut image = fixture();
        check(&image, 62).unwrap();
        assert!(check(&image, 183).is_err());
        for end in 0..image.len() {
            assert!(check(&image[..end], 62).is_err());
        }
        image[64..68].copy_from_slice(&3u32.to_le_bytes());
        assert!(check(&image, 62).is_err());
        image[64..68].copy_from_slice(&2u32.to_le_bytes());
        image[72..80].copy_from_slice(&120u64.to_le_bytes());
        image[96..104].copy_from_slice(&16u64.to_le_bytes());
        image.extend_from_slice(&1u64.to_le_bytes());
        image.extend_from_slice(&0u64.to_le_bytes());
        assert!(check(&image, 62).is_err());
    }
}
