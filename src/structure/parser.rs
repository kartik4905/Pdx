//! PDF Structure Parser
//! Author: kartik4905
//! Created: 2025-06-03 10:40:00 UTC

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use tracing::{debug, info, instrument};
use lopdf::{Object, ObjectId, Dictionary, Stream};

use crate::{
    error::{Error, Result},
    types::Document,
};

#[derive(Debug, Default)]
pub struct ParserStatistics {
    pub objects_parsed: usize,
    pub streams_processed: usize,
    pub duration_ms: Option<u64>,
}

pub struct PdfParser {
    offset: usize,
    cache: HashMap<ObjectId, Object>,
    stats: ParserStatistics,
}

impl PdfParser {
    pub fn new() -> Self {
        Self {
            offset: 0,
            cache: HashMap::new(),
            stats: ParserStatistics::default(),
        }
    }

    #[instrument(skip(self, input))]
    pub fn parse<R: Read + Seek>(&mut self, input: &mut R) -> Result<Document> {
        info!("Starting PDF document parsing");
        let start_time = std::time::Instant::now();

        let version = self.parse_header(input)?;
        let mut objects = HashMap::new();

        while let Some((object_id, object)) = self.parse_next_object(input)? {
            self.cache.insert(object_id, object.clone());
            objects.insert(object_id, object);
            self.stats.objects_parsed += 1;
        }

        self.parse_xref_tables(input)?;
        let trailer = self.parse_trailer(input)?;

        self.stats.duration_ms = Some(start_time.elapsed().as_millis() as u64);
        info!("PDF document parsing completed");

        Ok(Document {
            path: Default::default(),
            size: trailer.get(b"Size").and_then(|obj| obj.as_i64().ok()).unwrap_or(0) as usize,
            version,
            metadata: trailer,
            content: objects,
            state: Default::default(),
        })
    }

    fn parse_dictionary<R: Read + Seek>(&mut self, input: &mut R) -> Result<Dictionary> {
        let mut dict = Dictionary::new();
        loop {
            self.skip_whitespace(input)?;
            let key = self.parse_name(input)?;
            let val = self.parse_object_value(input)?;
            if let Object::Name(name) = key {
                dict.set(name.as_bytes().to_vec(), val);
            } else {
                return Err(Error::Parse("Invalid key in dictionary"));
            }
            let mut end = [0u8; 2];
            input.read_exact(&mut end)?;
            if &end == b">>" {
                break;
            }
            input.seek(SeekFrom::Current(-2))?;
        }
        Ok(dict)
    }

    fn parse_stream_data<R: Read + Seek>(&mut self, input: &mut R, dict_obj: Dictionary) -> Result<Stream> {
        let length = match dict_obj.get(b"Length") {
            Some(Object::Integer(n)) => *n as usize,
            _ => return Err(Error::Parse("Invalid or missing Length for stream")),
        };

        let mut data = vec![0u8; length];
        input.read_exact(&mut data)?;

        self.stats.streams_processed += 1;
        Ok(Stream::new(dict_obj, data))
    }
}
