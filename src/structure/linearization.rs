//! PDF linearization handler implementation for anti-forensics
//! Author: kartik4091

use std::collections::HashMap;
use tracing::{debug, info, instrument};
use lopdf::{Object, Dictionary};

use crate::{
    error::{Error, Result},
    types::{Document},
};

pub struct LinearizationHandler;

impl LinearizationHandler {
    pub fn parse_linearization_dict(&self, dict: &Dictionary) -> Result<HashMap<&[u8], i64>> {
        let get_i64 = |key: &[u8]| match dict.get(key) {
            Some(Object::Integer(i)) => Ok(*i as i64),
            _ => Err(Error::Parse(format!("Missing or invalid {:?} entry", key))),
        };

        let mut linearization_params = HashMap::new();
        linearization_params.insert(b"L", get_i64(b"L")?);
        linearization_params.insert(b"H", get_i64(b"H")?);
        linearization_params.insert(b"O", get_i64(b"O")?);

        Ok(linearization_params)
    }
}
