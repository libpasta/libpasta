/// Native Rust implementation of scrypt. 
pub use self::native::Scrypt;

/// Native Rust implementation of scrypt.
mod native {
    #![allow(cast_possible_truncation)]

    use primitives::Primitive;
    use primitives::sod::Sod;

    use ring_pwhash::scrypt;
    use serde_mcf::Hashes;

    use std::fmt;

    /// Struct holding `scrypt` parameters.
    ///
    /// This implementation is backed by `ring_pwhash`.
    pub struct Scrypt {
        /// Parameters as a byte array.
        /// `log_n` is one byte, `r` and `p` are 4 bytes.
        /// Use the `convert_params` macro to convert between the array and the
        /// tuple.
        pbytes: [u8; 9],
        /// Parameters used internally by `ring_pwhash`.
        params: scrypt::ScryptParams,
    }

    lazy_static! {
        static ref DEFAULT: Scrypt = {
            Scrypt::new_impl(14, 8, 1)
        };
    }

    macro_rules! convert_params {
        ($log_n:ident, $r:ident,$p:ident) => (
            [ $log_n, ($r >> 24) as u8, ($r >> 16) as u8, ($r >>  8) as u8, $r as u8, ($p >> 24) as u8, 
              ($p >> 16) as u8, ($p >>  8) as u8, ($p & 0xff) as u8 ]
        );
        ($pb:expr) => (
            ($pb[0], 
             ($pb[1] as u32) << 24  | ($pb[2] as u32) << 16 | ($pb[3] as u32) << 8 | ($pb[4] as u32),
             ($pb[5] as u32) << 24 | ($pb[6] as u32) << 16 | ($pb[7] as u32) << 8 | ($pb[8] as u32)
             )
        )
    }

    impl ::primitives::PrimitiveImpl for Scrypt {
        /// Compute the scrypt hash
        fn compute<'a>(&'a self, password: &[u8], salt: &[u8]) -> Vec<u8> {
            let mut hash = [0_u8; 32];
            scrypt::scrypt(password, salt, &self.params, &mut hash);
            hash[..32].to_vec()
        }

        /// Convert parameters into a vector of (key, value) tuples
        /// for serializing.
        fn params_as_vec(&self) -> Vec<(&'static str, String)> {
            let (log_n, r, p) = convert_params!(self.pbytes);
            vec![
                ("log_n", log_n.to_string()),
                ("r", r.to_string()),
                ("p", p.to_string()),
            ]
        }

        fn hash_id(&self) -> Hashes {
            Hashes::ScryptMcf
        }

    }

    impl fmt::Debug for Scrypt {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            let params = convert_params!(self.pbytes);
            write!(f, "Scrypt, N: {}, r: {}, p: {}", 1 << params.0, params.1, params.2)
        }
    }

    impl Scrypt {
        /// Gets the default scrypt instance.
        pub fn default() -> Primitive {
            Primitive(Sod::Static(&*DEFAULT))
        }

        fn new_impl(log_n: u8, r: u32, p: u32) -> Self {
            Scrypt {
                pbytes: convert_params!(log_n, r, p),
                params: scrypt::ScryptParams::new(log_n, r, p),
            }
        }

        /// Create  a new scrypt instance.
        pub fn new(log_n: u8, r: u32, p: u32) -> Primitive {
            Self::new_impl(log_n, r, p).into()
        }

        /// Create  a new Scrypt instance from an array of bytes, the compact
        /// format used by scrypt.
        pub fn from_bytes(bytes: [u8; 9]) -> Primitive {
            let (log_n, r, p) = convert_params!(bytes);
            Scrypt {
                pbytes: bytes,
                params: scrypt::ScryptParams::new(log_n, r, p),
            }.into()
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
        let params = super::Scrypt::default();
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
}

benches!(Scrypt);
