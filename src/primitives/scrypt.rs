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
            vec![("ln", log_n.to_string()), ("r", r.to_string()), ("p", p.to_string())]
        }

        fn hash_id(&self) -> Hashes {
            Hashes::Scrypt
        }
    }

    impl fmt::Debug for Scrypt {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            let params = convert_params!(self.pbytes);
            write!(f,
                   "Scrypt, N: {}, r: {}, p: {}",
                   1 << params.0,
                   params.1,
                   params.2)
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
                }
                .into()
        }
    }

}


#[cfg(test)]
mod test {
    use data_encoding;
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

    fn scrypt_test(password: &str, salt: &str, n: u32, r: u32, p: u32, _output_len: u32, expected: &str) {
        let scrypt = super::Scrypt::new(f32::log2(n as f32) as u8, r, p);
        let hash = scrypt.compute(password.as_bytes(), salt.as_bytes());
        let expected = expected.replace(" ", "").to_uppercase();
        println!("{}", expected);
        let expected = data_encoding::base16::decode(expected.as_bytes()).unwrap();
        assert_eq!(&expected[..32], &hash[..]);
    }

    #[test]
    fn scrypt_test_vectors() {
        scrypt_test("", "", 16, 1, 1, 64, "\
        77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97\
        f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42\
        fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17\
        e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06");

        scrypt_test("password", "NaCl", 1024, 8, 16, 64, "\
        fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe\
        7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62\
        2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da\
        c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40"); 
    }

    #[test] #[cfg(feature = "long_tests")]
    fn scrypt_test_vectors_long() {
        scrypt_test("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64,"\
        70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb\
        fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2\
        d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9\
        e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87");
        scrypt_test("pleaseletmein", "SodiumChloride", 1048576, 8, 1, 64,"\
        21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81\
        ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47\
        8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3\
        37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4");
    }
}

benches!(Scrypt);
