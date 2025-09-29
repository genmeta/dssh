use std::{io, marker::PhantomData};

use bytes::{Buf, BytesMut};
use serde::{Deserialize, Serialize};
use tokio_util::codec;

#[derive(Debug)]
pub struct CborDecoder<'de, T> {
    buf: BytesMut,
    _t: PhantomData<&'de T>,
}

impl<'de, T> Default for CborDecoder<'de, T> {
    fn default() -> Self {
        Self {
            buf: Default::default(),
            _t: Default::default(),
        }
    }
}

impl<'de, T: Deserialize<'de>> codec::Decoder for CborDecoder<'de, T> {
    type Item = T;

    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.buf.is_empty() {
            self.buf = std::mem::take(src)
        } else {
            self.buf.extend_from_slice(src);
            src.clear();
        }
        let mut cursor = io::Cursor::new(&self.buf);
        let mut de = serde_cbor::Deserializer::from_reader(&mut cursor);
        match T::deserialize(&mut de) {
            Ok(t) => {
                self.buf.advance(cursor.position() as usize);
                Ok(Some(t))
            }
            Err(e) if e.is_eof() => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to decode CBOR: {e}"),
            )),
        }
    }
}

#[derive(Debug)]
pub struct CborEncoder<T>(PhantomData<T>);

impl<T> Default for CborEncoder<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: Serialize> codec::Encoder<T> for CborEncoder<T> {
    type Error = serde_cbor::Error;

    fn encode(&mut self, item: T, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        let mut buf = Vec::new();
        serde_cbor::ser::to_writer(&mut buf, &item)?;
        dst.extend_from_slice(&buf);
        Ok(())
    }
}
