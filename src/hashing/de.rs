//! Serde deserialize for password hashes
//!
//! The output from a hashing algorithm typically includes: the hash itself,
//! the salt, and the parameters used in the hashing.
//! This allows us to store the output in an unambigous fashion.
//!
//! However, not all algorithms had this foresight, and many instead wrote
//! simple formats which simply included the hash output and salt concatenated.
//!
//! This module attempts to deserialize various formats into the `libpasta`
//! supported form.

use hashing::{Algorithm, Output};
use primitives::Primitive;

use serde::{Deserialize, Deserializer};
use serde::de::{self, Visitor};
use serde::de::Error;
use serde_mcf;
use serde_mcf::{base64, base64bcrypt};

use std::fmt;


/// Currently supported hashing variants.
///
/// `Bcrypt`: `$(2a|2b|2x|2y)$<cost>$<salthash>`
///    where salthash is a non-standard base64 encoding.
/// `Mcf`: `$<alg-id>$<params map>$<salt>$<hash>`
/// `Scrypt`: `$(scrypt|rscrypt)$<params>$<salt>$<hash>`
/// `Pasta`: `$<MCF-hash>` or `$!<Pasta-hash>` (recursively)
enum SupportedVariants {
    Bcrypt(serde_mcf::Hashes),
    Mcf(serde_mcf::Hashes),
    Scrypt,
    Pasta(PastaVariants),
}

/// A Pasta hash is either a sing hash parameterisation, or a recursive
/// structure, containing many hash parameters.
enum PastaVariants {
    Single,
    Nested,
}

static VAR_STRUCT: [&'static str; 2] = ["variant", "remaining"];

// The *Fields structs define the layout of the various supported variants,
// as detailed above. After parsing the algorithm identifier, one of these
// structs are used to attempt to deserialize.

#[derive(Deserialize)]
struct BcryptFields {
    cost: u32,
    #[serde(with = "base64bcrypt")]
    salthash: (Vec<u8>, Vec<u8>),
}

#[derive(Deserialize)]
struct McfFields {
    params: serde_mcf::Map<String, serde_mcf::Value>,
    #[serde(with = "base64")]
    pub salt: Vec<u8>,
    #[serde(with = "base64")]
    pub hash: Vec<u8>,
}

#[derive(Deserialize)]
struct ScryptFields {
    #[serde(with = "base64")]
    params: Vec<u8>,
    #[serde(with = "base64")]
    pub salt: Vec<u8>,
    #[serde(with = "base64")]
    pub hash: Vec<u8>,
}



/// The nested Pasta format is specified by a $<id>$<params> parameterising the
/// outer layer hash algorithm, followed by another set of algorithm parameters.
/// This inner hash may also a further layer of nested params.
#[derive(Deserialize)]
struct PastaNest {
    outer_id: serde_mcf::Hashes,
    outer_params: serde_mcf::Map<String, serde_mcf::Value>,
    inner: Output,
}

// Deserialize Output using OutputVisitor
impl<'de> Deserialize<'de> for Output {
    fn deserialize<D>(deserializer: D) -> Result<Output, D::Error>
        where D: Deserializer<'de>
    {
        deserializer.deserialize_struct("var_container", &VAR_STRUCT, OutputVisitor)
    }
}

/// `OutputVisitor` does most of the heavy lifting of the deserializing.
/// First, we use the `SupportedVariants` enum to identify which type of hash
/// we are dealing with.
/// Second, the remaining values are deserialized into the suitable *Field struct.
/// Finally, the fields are unified into the `Output` struct and returned.
struct OutputVisitor;
impl<'de> Visitor<'de> for OutputVisitor {
    type Value = Output;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an identifier")
    }

    fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
        where V: de::MapAccess<'de>
    {

        // The first step is to detect which variant we are dealing with.
        let _: Option<String> = map.next_key()?;
        let var: SupportedVariants = map.next_value()?;

        match var {
            // Deserialize each variant using specific format.
            // Note that let fields: SomeFields = map.next_value()?;
            // is automatically calling the deserializer for SomeFields.
            SupportedVariants::Bcrypt(_) => {
                let _: Option<String> = map.next_key()?;
                let fields: BcryptFields = map.next_value()?;
                let prim = ::primitives::Bcrypt::new(fields.cost);
                Ok(Output {
                    alg: Algorithm::Single(prim),
                    salt: fields.salthash.0,
                    hash: fields.salthash.1,
                })
            }
            SupportedVariants::Mcf(var) => {
                let _: Option<String> = map.next_key()?;
                let fields: McfFields = map.next_value()?;
                let prim = ::primitives::Primitive::from((&var, &fields.params));
                if prim == ::primitives::Poisoned.into() {
                    #[allow(use_debug)]
                    return Err(V::Error::custom(format!("failed to deserialize as {:?}", var)));
                }
                Ok(Output {
                    alg: Algorithm::Single(prim),
                    salt: fields.salt,
                    hash: fields.hash,
                })
            }
            SupportedVariants::Scrypt => {
                let _: Option<String> = map.next_key()?;
                let fields: ScryptFields = map.next_value()?;
                let mut scrypt_bytes = [0_u8; 9];
                scrypt_bytes.copy_from_slice(&fields.params);
                let prim = ::primitives::Primitive::from((&serde_mcf::Hashes::Scrypt,
                                                          scrypt_bytes));
                Ok(Output {
                    alg: Algorithm::Single(prim),
                    salt: fields.salt,
                    hash: fields.hash,
                })
            }
            SupportedVariants::Pasta(var) => {
                // unimplemented!();
                match var {
                    PastaVariants::Single => {
                        let _: Option<String> = map.next_key()?;
                        let output: serde_mcf::McfHash = map.next_value()?;
                        let prim = ::primitives::Primitive::from((&output.algorithm,
                                                                  &output.parameters));
                        Ok(Output {
                            alg: Algorithm::Single(prim),
                            salt: output.salt,
                            hash: output.hash,
                        })
                    }
                    PastaVariants::Nested => {
                        let _: Option<String> = map.next_key()?;
                        // Note that in this case, PastaNest deserializer is
                        // recursively deserializing PastaVariants until
                        // reaching the end.
                        let fields: PastaNest = map.next_value()?;
                        let prim = ::primitives::Primitive::from((&fields.outer_id,
                                                                  &fields.outer_params));
                        Ok(Output {
                            alg: Algorithm::Nested {
                                outer: prim,
                                inner: Box::new(fields.inner.alg.clone()),
                            },
                            salt: fields.inner.salt,
                            hash: fields.inner.hash,
                        })
                    }
                }
            }
        }
    }
}

impl<'de> Deserialize<'de> for SupportedVariants {
    fn deserialize<D>(deserializer: D) -> Result<SupportedVariants, D::Error>
        where D: Deserializer<'de>
    {
        deserializer.deserialize_identifier(VariantVisitor)

    }
}

/// Visitor to deserialize the `SupportedVariants` enum.
/// Currently is able to detect the variant by how the string starts.
/// For example, `$$` or `$!$` indicates a Pasta variant, whereas `$2a` would
/// be a regular `Bcrypt` hash.
struct VariantVisitor;
impl<'de> Visitor<'de> for VariantVisitor {
    type Value = SupportedVariants;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an identifier")
    }

    fn visit_borrowed_str<E>(self, val: &str) -> Result<Self::Value, E>
        where E: Error
    {
        let var = match val {
            "" => SupportedVariants::Pasta(PastaVariants::Single),
            "!" => SupportedVariants::Pasta(PastaVariants::Nested),
            var @ "2" | var @ "2a" | var @ "2b" | var @ "2x" | var @ "2y" => {
                let variant = serde_mcf::Hashes::from_id(var).ok_or_else(|| {
                        error!("could not find MCF variant for supposed bcrypt hash");
                        E::custom(format!("unknown MCF variant: {}", var))
                    })?;
                SupportedVariants::Bcrypt(variant)
            }
            _var @ "scrypt" | _var @ "rscrypt" => SupportedVariants::Scrypt,
            var => {
                let variant = serde_mcf::Hashes::from_id(var).ok_or_else(|| E::custom(format!("unknown MCF variant: {}", var)))?;
                SupportedVariants::Mcf(variant)
            }
        };
        Ok(var)
    }
}

// The deserializing of a `Primitive` is used in the nested `Pasta` variants.
impl<'de> Deserialize<'de> for Primitive {
    fn deserialize<D>(deserializer: D) -> Result<Primitive, D::Error>
        where D: Deserializer<'de>
    {
        #[derive(Deserialize)]
        struct PrimitiveStruct {
            id: serde_mcf::Hashes,
            params: serde_mcf::Map<String, serde_mcf::Value>,
        }
        let prim = PrimitiveStruct::deserialize(deserializer)?;
        Ok((&prim.id, &prim.params).into())
    }
}
