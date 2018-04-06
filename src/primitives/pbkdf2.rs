#[cfg(feature = "fastpbkdf2")]
pub use self::fastpbkdf2::Pbkdf2;

#[cfg(not(feature = "fastpbkdf2"))]
pub use self::ring_pbkdf2::Pbkdf2 as Pbkdf2;

pub use self::ring_pbkdf2::Pbkdf2 as RingPbkdf2;

/// Native Rust implementation of PBKDF2.
mod ring_pbkdf2 {
    use primitives::{Primitive, PrimitiveImpl};
    use sod::Sod;

    use ring::{digest, pbkdf2};
    use serde_mcf::Hashes;

    use std::fmt;
    use std::sync::Arc;

    use super::super::hash_to_id;

    /// Struct holding `PBKDF2` parameters.
    ///
    /// This implementation is backed by `ring`.
    pub struct Pbkdf2 {
        iterations: u32,
        algorithm: &'static digest::Algorithm,
    }


    impl Pbkdf2 {
        /// Create a new PBKDF2 instance using defaults.
        pub fn default() -> Primitive {
            Primitive(Sod::Dynamic(Arc::clone(&DEFAULT)))
        }

        /// Create  a new PBKDF2 instance.
        pub fn new(iterations: u32, algorithm: &'static digest::Algorithm) -> Primitive {
            Self::new_impl(iterations, algorithm).into()
        }

        fn new_impl(iterations: u32, algorithm: &'static digest::Algorithm) -> Self {
            Self {
                iterations: iterations,
                algorithm: algorithm,
            }
        }
    }

    lazy_static! {
        static ref DEFAULT: Arc<Box<PrimitiveImpl>> = {
            Arc::new(Box::new(Pbkdf2::new_impl(10_000, &digest::SHA256)))
        };
    }

    impl ::primitives::PrimitiveImpl for Pbkdf2 {
        /// Compute the scrypt hash
        fn compute<'a>(&'a self, password: &[u8], salt: &[u8]) -> Vec<u8> {
            let mut hash = vec![0_u8; 32];
            pbkdf2::derive(self.algorithm, self.iterations, salt, password, &mut hash);
            hash
        }

        /// Convert parameters into a vector of (key, value) tuples
        /// for serializing.
        fn params_as_vec(&self) -> Vec<(&'static str, String)> {
            vec![("n", self.iterations.to_string())]
        }

        fn hash_id(&self) -> Hashes {
            match hash_to_id(self.algorithm).as_ref() {
                "SHA1" => Hashes::Pbkdf2Sha1,
                "SHA256" => Hashes::Pbkdf2Sha256,
                "SHA512" => Hashes::Pbkdf2Sha512,
                _ => panic!("unexpected digest algorithm"),
            }
        }
    }

    impl fmt::Debug for Pbkdf2 {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            write!(f,
                   "PBKDF2-{:?}, iterations: {}",
                   self.algorithm,
                   self.iterations)
        }
    }
}


/// C implementation of PBKDF2.
#[cfg(feature = "fastpbkdf2")]
mod fastpbkdf2 {
    extern crate fastpbkdf2;
    use self::fastpbkdf2::*;

    use primitives::{Primitive, PrimitiveImpl};
    use sod::Sod;

    use ring::digest;
    use serde_mcf::Hashes;

    use std::fmt;
    use std::sync::Arc;

    use super::super::hash_to_id;

    /// Struct holding `PBKDF2` parameters.
    ///
    /// This implementation is backed by `fastpbkdf2`.
    pub struct Pbkdf2 {
        iterations: u32,
        algorithm: fn(&[u8], &[u8], u32, &mut [u8]),
        alg_id: &'static str,
    }

    lazy_static! {
        static ref DEFAULT: Arc<Box<PrimitiveImpl>> = {
            Arc::new(Box::new(Pbkdf2::new_impl(10_000, &digest::SHA256)))
        };
    }

    impl Pbkdf2 {
        /// Create a new PBKDF2 instance using defaults.
        pub fn default() -> Primitive {
            Primitive(Sod::Dynamic(Arc::clone(&DEFAULT)))
        }

        /// Create  a new PBKDF2 instance.
        pub fn new(iterations: u32, algorithm: &'static digest::Algorithm) -> Primitive {
            Self::new_impl(iterations, algorithm).into()
        }

        fn new_impl(iterations: u32, algorithm: &'static digest::Algorithm) -> Self {
            match hash_to_id(algorithm).as_ref() {
                "SHA1" => {
                    Self {
                        iterations: iterations,
                        algorithm: pbkdf2_hmac_sha1,
                        alg_id: "SHA1",
                    }
                }
                "SHA256" => {
                    Self {
                        iterations: iterations,
                        algorithm: pbkdf2_hmac_sha256,
                        alg_id: "SHA256",
                    }
                }
                "SHA512" => {
                    Self {
                        iterations: iterations,
                        algorithm: pbkdf2_hmac_sha512,
                        alg_id: "SHA512",
                    }
                }
                _ => panic!("unexpected digest algorithm"),
            }
        }
    }

    impl ::primitives::PrimitiveImpl for Pbkdf2 {
        /// Compute the scrypt hash
        fn compute<'a>(&'a self, password: &[u8], salt: &[u8]) -> Vec<u8> {
            let mut hash = vec![0_u8; 32];
            (self.algorithm)(password, salt, self.iterations, &mut hash);
            hash
        }

        /// Convert parameters into a vector of (key, value) tuples
        /// for serializing.
        fn params_as_vec(&self) -> Vec<(&'static str, String)> {
            vec![("n", self.iterations.to_string())]
        }

        fn hash_id(&self) -> Hashes {
            match self.alg_id {
                "SHA1" => Hashes::Pbkdf2Sha1,
                "SHA256" => Hashes::Pbkdf2Sha256,
                "SHA512" => Hashes::Pbkdf2Sha512,
                _ => panic!("unexpected digest algorithm"),
            }
        }
    }

    impl fmt::Debug for Pbkdf2 {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            write!(f,
                   "PBKDF2-{:?}, iterations: {}",
                   self.alg_id,
                   self.iterations)
        }
    }
}


#[cfg(test)]
mod test {
    use ::hashing::*;
    use ring::digest;
    use serde_mcf;

    #[test]
    fn sanity_check() {
        let password = "hunter2";
        let params = super::Pbkdf2::default();
        println!("{:?}", params);
        let salt = ::get_salt();
        let hash = params.compute(password.as_bytes(), &salt);
        let hash2 = params.compute(password.as_bytes(), &salt);
        assert_eq!(hash, hash2);
        let out = Output {
            alg: Algorithm::Single(params.into()),
            salt: salt,
            hash: hash,
        };
        println!("{:?}", serde_mcf::to_string(&out).unwrap());
    }

    #[test]
    fn sanity_check_ring() {
        let password = "hunter2";
        let params = super::RingPbkdf2::default();
        println!("{:?}", params);
        let salt = ::get_salt();
        let hash = params.compute(password.as_bytes(), &salt);
        let hash2 = params.compute(password.as_bytes(), &salt);
        assert_eq!(hash, hash2);
        let out = Output {
            alg: Algorithm::Single(params.into()),
            salt: salt,
            hash: hash,
        };
        println!("{:?}", serde_mcf::to_string(&out).unwrap());
    }

    macro_rules! primitive_round_trip {
        ($prim:expr) => (
            let hash = serde_mcf::to_string(&$prim.hash(&"hunter2")).unwrap();
            let _output: Output = serde_mcf::from_str(&hash).unwrap();
        )
    }

    #[test]
    fn pbkdf2_params() {
        let params = Algorithm::Single(super::Pbkdf2::new(1_000, &digest::SHA1));
        primitive_round_trip!(params);

        let params = Algorithm::Single(super::Pbkdf2::new(1_000, &digest::SHA256));
        primitive_round_trip!(params);

        let params = Algorithm::Single(super::Pbkdf2::new(1_000, &digest::SHA512));
        primitive_round_trip!(params);

        let params = Algorithm::Single(super::RingPbkdf2::new(1_000, &digest::SHA1));
        primitive_round_trip!(params);

        let params = Algorithm::Single(super::RingPbkdf2::new(1_000, &digest::SHA256));
        primitive_round_trip!(params);

        let params = Algorithm::Single(super::RingPbkdf2::new(1_000, &digest::SHA512));
        primitive_round_trip!(params);

    }
}

#[cfg(features = "bench")]
mod ring_bench {
    use super::*;
    benches!(RingPbkdf2);
}

#[cfg(features = "bench")]
mod fast_bench {
    use super::*;
    benches!(Pbkdf2);
}
