//! Framing between the shim and the daemon.
//!
//! Each message is one line of JSON. If it has `"blob_len": N`, N raw bytes follow. One
//! request at a time per connection.

use std::io::{self, BufRead, Read, Write};

use serde_json::{Map, Value};

pub const MAX_LINE: u64 = 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Reads one message. `None` means the peer closed the connection between messages.
pub fn read_message(reader: &mut impl BufRead) -> io::Result<Option<Map<String, Value>>> {
    let mut line = Vec::new();
    reader.take(MAX_LINE).read_until(b'\n', &mut line)?;
    if line.is_empty() {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        return Err(invalid("message too long or cut off"));
    }
    match serde_json::from_slice(&line) {
        Ok(Value::Object(map)) => Ok(Some(map)),
        _ => Err(invalid("message is not a JSON object")),
    }
}

/// Writes one message; the caller writes the blob bytes after it, if it announced any.
pub fn write_message(writer: &mut impl Write, message: &Value) -> io::Result<()> {
    let mut line = serde_json::to_vec(message)?;
    line.push(b'\n');
    if line.len() as u64 > MAX_LINE {
        return Err(invalid("message too long"));
    }
    writer.write_all(&line)?;
    writer.flush()
}

/// The announced blob length. Present but not an unsigned integer is an error.
pub fn blob_len(message: &Map<String, Value>) -> io::Result<Option<u64>> {
    match message.get("blob_len") {
        None => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| invalid("bad blob_len")),
    }
}

/// Copies exactly `len` bytes.
pub fn copy_exact(reader: &mut impl Read, writer: &mut impl Write, len: u64) -> io::Result<()> {
    let copied = io::copy(&mut reader.take(len), writer)?;
    if copied != len {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "blob cut off"));
    }
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_with_blob() {
        let mut buf = Vec::new();
        write_message(&mut buf, &json!({"id": 1, "blob_len": 3})).unwrap();
        buf.extend_from_slice(b"abc");
        write_message(&mut buf, &json!({"id": 2})).unwrap();
        let mut r = &buf[..];
        let m = read_message(&mut r).unwrap().unwrap();
        let mut blob = Vec::new();
        copy_exact(&mut r, &mut blob, blob_len(&m).unwrap().unwrap()).unwrap();
        assert_eq!(blob, b"abc");
        assert_eq!(read_message(&mut r).unwrap().unwrap()["id"], 2);
        assert!(read_message(&mut r).unwrap().is_none());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(read_message(&mut &b"[1]\n"[..]).is_err());
        assert!(read_message(&mut &b"{\"id\":1}"[..]).is_err());
        let long = vec![b'x'; MAX_LINE as usize + 10];
        assert!(read_message(&mut &long[..]).is_err());
        let m = read_message(&mut &b"{\"blob_len\":-1}\n"[..]).unwrap().unwrap();
        assert!(blob_len(&m).is_err());
        assert!(copy_exact(&mut &b"ab"[..], &mut Vec::new(), 3).is_err());
    }
}
