pub use self::hmac_ring::Hmac;

mod hmac_ring {
    use key::Store;
    use primitives::Primitive;

    use data_encoding::base64;
    use ring::{digest, hkdf, hmac, rand};
    use serde_mcf::Hashes;

    use std::fmt;

    /// Password storage strengthening using HMAC.
    ///
    /// This struct holds the parameters used.
    /// Represents the `ring` implementation.
    pub struct Hmac {
        key: hmac::SigningKey,
        key_id: [u8; 32],
    }

    impl Hmac {
        /// Construct a new `Hmac` instance with a specified key
        pub fn with_key(h: &'static digest::Algorithm, key: &[u8]) -> Primitive {
            let mut key_id = [0_u8; 32];
            key_id.copy_from_slice(digest::digest(&digest::SHA512_256, key).as_ref());
            Self {
                key: hmac::SigningKey::new(h, key),
                key_id,
            }.into()
        }

        /// Gets a default HMAC instance, generating a fresh new key.
        pub fn default() -> Primitive {
            Self::new().into()
        }

        fn new() -> Self {
            let rng = rand::SystemRandom::new();
            let mut key_id = [0_u8; 32];
            let key = hmac::SigningKey::generate_serializable(&digest::SHA256, &rng, &mut key_id).expect("could not generate random bytes for key");
            let digest = digest::digest(&digest::SHA512_256, &key_id);
            ::key::KEY_STORE.insert(base64::encode_nopad(digest.as_ref()), &key_id[..]);
            key_id.copy_from_slice(digest.as_ref());
            Self {
                key, key_id,
            }
        }

        fn key_id(&self) -> String {
            base64::encode_nopad(&self.key_id)
        }

    }

    impl ::primitives::PrimitiveImpl for Hmac {
        /// Compute the scrypt hash
        fn compute(&self, password: &[u8], _salt: &[u8]) -> Vec<u8> {
            let mut hash = vec![0_u8; 32];
            hkdf::extract_and_expand(&self.key, password, b"libpasta password hashing", &mut hash);
            hash
        }

        /// Convert parameters into a vector of (key, value) tuples
        /// for serializing.
        fn params_as_vec(&self) -> Vec<(&'static str, String)> {
            vec![
                ("key_id", self.key_id()),
                ("h", super::super::hash_to_id(self.key.digest_algorithm())),
            ]
        }

        fn hash_id(&self) -> Hashes {
            Hashes::Hmac
        }
    }

    impl fmt::Debug for Hmac {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            write!(f, "Hmac, KeyID: {}, Hash: {}", self.key_id(), super::super::hash_to_id(self.key.digest_algorithm()))
        }
    }

    impl PartialEq for Hmac {
        fn eq(&self, rhs: &Self) -> bool {
            self.key_id() == rhs.key_id()
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
        let inner_params = ::primitives::scrypt::Scrypt::default();
        let salt = ::get_salt();
        let hash = hmac_params.compute(&inner_params.compute(password.as_bytes(), &salt), &salt);
        let hash2 = hmac_params.compute(&inner_params.compute(password.as_bytes(), &salt), &salt);
        let params = Algorithm::Nested { outer: hmac_params.into(), inner: Box::new(Algorithm::Single(inner_params.into())) };
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
        let algorithm = Algorithm::Nested { outer: super::Hmac::default().into(), inner: Box::new(Algorithm::Single(::primitives::Scrypt::default())) };
        let hash = algorithm.hash(password.to_string().into()).unwrap();
        assert!(hash.verify(password.to_string().into()));
    }

}

benches!(Hmac);
