use bincode::Options;
use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::de::DeserializeOwned;
use std::io::{self, Cursor, ErrorKind};

const DEFAULT_BUF: usize = 1024;

/// An asynchronous reader that deserializes values using bincode varint encoding.
pub struct StdcodeReader<R: AsyncRead + Unpin> {
    reader: R,
    buf: Vec<u8>,
    filled: usize,
    max_size: usize,
}

impl<R: AsyncRead + Unpin> StdcodeReader<R> {
    /// Creates a new `StdcodeReader` with no maximum buffer size.
    pub fn new(reader: R) -> Self {
        Self::with_max_size(reader, usize::MAX)
    }

    /// Creates a new `StdcodeReader` with a specified maximum buffer size.
    pub fn with_max_size(reader: R, max_size: usize) -> Self {
        Self {
            reader,
            buf: vec![0u8; DEFAULT_BUF],
            filled: 0,
            max_size,
        }
    }

    /// Reads the next value of type `T` from the stream.
    pub async fn read<T: DeserializeOwned>(&mut self) -> io::Result<T> {
        loop {
            let mut cursor = Cursor::new(&self.buf[..self.filled]);
            // Attempt to decode from the bytes we already have
            match bincode::options()
                .with_varint_encoding()
                .allow_trailing_bytes()
                .deserialize_from::<_, T>(&mut cursor)
            {
                Ok(val) => {
                    let consumed = cursor.position() as usize;

                    // Shift remaining bytes to the front
                    self.buf.copy_within(consumed..self.filled, 0);
                    self.filled -= consumed;
                    return Ok(val);
                }
                Err(e) if matches!(e.as_ref(), bincode::ErrorKind::Io(_)) => {
                    // Not enough data yet: fallthrough to read more
                }
                Err(e) => return Err(io::Error::new(ErrorKind::InvalidData, e)),
            }

            // Expand buffer if full
            if self.filled == self.buf.len() {
                self.buf.resize(self.buf.len() * 2, 0);
                if self.buf.len() > self.max_size {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "ran out of space trying to decode",
                    ));
                }
            }

            // Read more data into the buffer
            let n = self.reader.read(&mut self.buf[self.filled..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            self.filled += n;
        }
    }
}

/// An asynchronous writer that serializes values using stdcode encoding.
pub struct StdcodeWriter<W: AsyncWrite + Unpin> {
    writer: W,
    buf: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> StdcodeWriter<W> {
    /// Creates a new `StdcodeWriter`.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            buf: vec![],
        }
    }

    /// Serializes a value and writes it to the underlying writer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if serialization fails or if the write to the
    /// underlying writer fails.
    pub async fn write<T: serde::Serialize>(&mut self, value: T) -> io::Result<()> {
        // Serialize into the internal buffer
        bincode::options()
            .with_varint_encoding()
            .serialize_into(&mut self.buf, &value)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

        // Write all bytes and clear buffer
        self.writer.write_all(&self.buf).await?;
        self.buf.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bipe::bipe;

    #[test]
    fn trivial() {
        pollster::block_on(async {
            let (write, read) = bipe(100);
            let (mut read, mut write) = (StdcodeReader::new(read), StdcodeWriter::new(write));
            for _ in 0..10 {
                write.write(1u64).await.unwrap();
            }
            for _ in 0..10 {
                let resp: u64 = read.read().await.unwrap();
                assert_eq!(resp, 1);
            }
        })
    }
}
