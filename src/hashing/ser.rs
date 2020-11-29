/// Serialization of password hashes using serde.
///
/// Compared to the complext deserialization logic, this is comparatively
/// simpler, since we only support serializing to our own standardised format.
///
/// In practice, `serde_mcf` will be used to produce the serialized output.
/// However, this same structure can help to produce configuration files.
use hashing::{Algorithm, Output};
use primitives::Primitive;

use serde::ser::{SerializeStruct, SerializeStructVariant};
use serde::{Serialize, Serializer};
use serde_mcf;
use serde_mcf::{Hashes, Map, Value};

#[derive(Serialize)]
struct Base64Encoded<'a>(#[serde(with = "serde_mcf::base64")] &'a [u8]);

impl Serialize for Output {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Output", 2)?;
        state.serialize_field("algorithm", &self.alg)?;
        state.serialize_field("salt", &Base64Encoded(&self.salt))?;
        state.serialize_field("hash", &Base64Encoded(&self.hash))?;
        state.end()
    }
}

impl<'a> Serialize for Algorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Algorithm::Single(ref alg) => {
                let mut state = serializer.serialize_struct_variant("algorithm", 0, "", 2)?;
                let (algorithm, params): (Hashes, Map<String, Value>) = alg.into();
                state.serialize_field("id", &algorithm)?;
                state.serialize_field("params", &params)?;
                state.end()
            }
            Algorithm::Nested {
                ref outer,
                ref inner,
            } => {
                let mut state = serializer.serialize_struct_variant("algorithm", 1, "!", 3)?;
                let (algorithm, params): (Hashes, Map<String, Value>) = outer.into();
                state.serialize_field("outer_id", &algorithm)?;
                state.serialize_field("outer_params", &params)?;
                state.serialize_field("inner", &inner)?;
                state.end()
            }
        }
    }
}

impl<'a> Serialize for Primitive {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("primitive", 2)?;
        let (algorithm, params): (Hashes, Map<String, Value>) = self.into();
        state.serialize_field("id", &algorithm)?;
        state.serialize_field("params", &params)?;
        state.end()
    }
}
