pub use self::hmac_ring::Hmac;

mod hmac_ring {
    use config;
    use errors::*;
    use key;
    use key::Store;
    use primitives::Primitive;

    use ring::{digest, hkdf, hmac, rand};
    use serde_mcf::Hashes;

    use std::fmt;

    /// Password storage strengthening using HMAC.
    ///
    /// This struct holds the parameters used.
    /// Represents the `ring` implementation.
    pub struct Hmac {
        h: &'static digest::Algorithm,
        key: Option<hmac::SigningKey>,
        key_id: String,
    }

    impl Hmac {
        /// Construct a new `Hmac` instance with a specified key identifier
        pub fn with_key_id(h: &'static digest::Algorithm, key_id: &str) -> Primitive {
            Self {
                h: h,
                key: key::get_global().get_key(key_id).map(|k| hmac::SigningKey::new(h, &k)),
                key_id: key_id.to_string(),
            }.into()
        }

        /// Gets a default HMAC instance, generating a fresh new key.
        pub fn default() -> Primitive {
            Self::new().into()
        }

        fn new() -> Self {
            let rng = rand::SystemRandom::new();
            let mut key_bytes = [0_u8; 32];
            let key = hmac::SigningKey::generate_serializable(&digest::SHA256, &rng, &mut key_bytes)
                .expect("could not generate random bytes for key");
            let key_id = key::get_global().insert(&key_bytes);
            Self {
                h: &digest::SHA256,
                key: Some(key),
                key_id: key_id,
            }
        }
    }

    impl ::primitives::PrimitiveImpl for Hmac {
        /// Compute the scrypt hash
        fn compute(&self, password: &[u8], _salt: &[u8]) -> Vec<u8> {
            let mut hash = vec![0_u8; 32];
            let key = self.key.as_ref().expect_report("key not found");
            hkdf::extract_and_expand(key, password, b"libpasta password hashing", &mut hash);
            hash
        }

        /// Convert parameters into a vector of (key, value) tuples
        /// for serializing.
        fn params_as_vec(&self) -> Vec<(&'static str, String)> {
            vec![("key_id", self.key_id.clone()),
                 ("h", super::super::hash_to_id(self.h))]
        }

        fn hash_id(&self) -> Hashes {
            Hashes::Hmac
        }

        fn update_key(&self, config: &config::Config) -> Option<Primitive> {
            Some(Self {
                h: self.h,
                key: config.get_key(&self.key_id).map(|k| hmac::SigningKey::new(self.h, &k)),
                key_id: self.key_id.clone(),
            }.into())
        }
    }

    impl fmt::Debug for Hmac {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f,
                   "Hmac, KeyID: {}, Hash: {}",
                   self.key_id,
                   super::super::hash_to_id(self.h))
        }
    }
}


#[cfg(test)]
mod test {
    use ::hashing::*;
    use serde_mcf;

    #[test]
    fn sanity_check() {
        let password = "hunter2";
        let hmac_params = super::Hmac::default();
        println!("{:?}", hmac_params);
        let inner_params = ::primitives::scrypt::Scrypt::default();
        let salt = ::get_salt();
        let hash = hmac_params.compute(&inner_params.compute(password.as_bytes(), &salt), &salt);
        let hash2 = hmac_params.compute(&inner_params.compute(password.as_bytes(), &salt), &salt);
        let params = Algorithm::Nested {
            outer: hmac_params.into(),
            inner: Box::new(Algorithm::Single(inner_params.into())),
        };
        assert_eq!(hash, hash2);
        let out = Output {
            alg: params,
            salt: salt,
            hash: hash,
        };
        println!("{:?}", serde_mcf::to_string(&out).unwrap());
    }

    #[test]
    fn hash_verify_works() {
        let password = "hunter2";
        let algorithm = Algorithm::Nested {
            outer: super::Hmac::default().into(),
            inner: Box::new(Algorithm::Single(::primitives::Scrypt::default())),
        };
        let hash = algorithm.hash(&password.to_string().into());
        assert!(hash.verify(&password.to_string().into()));
    }

}

benches!(Hmac);
