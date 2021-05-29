/// Native Rust implementation of scrypt.
pub use self::native::Scrypt;

/// Native Rust implementation of scrypt.
mod native {
    use primitives::Primitive;
    use serde_mcf::Hashes;
    use sod::Sod;

    use std::fmt;

    /// Struct holding `scrypt` parameters.
    ///
    /// This implementation is backed by `ring_pwhash`.
    pub struct Scrypt {
        log_n: u8,
        r: u32,
        p: u32,
        /// Parameters used internally by `ring_pwhash`.
        params: scrypt::Params,
    }

    lazy_static! {
        static ref DEFAULT: Scrypt = Scrypt::new_impl(14, 8, 1);
    }

    impl ::primitives::PrimitiveImpl for Scrypt {
        /// Compute the scrypt hash
        fn compute<'a>(&'a self, password: &[u8], salt: &[u8]) -> Vec<u8> {
            let mut hash = [0_u8; 32];
            scrypt::scrypt(password, salt, &self.params, &mut hash).expect("scrypt failed");
            hash[..32].to_vec()
        }

        /// Convert parameters into a vector of (key, value) tuples
        /// for serializing.
        fn params_as_vec(&self) -> Vec<(&'static str, String)> {
            vec![
                ("ln", self.log_n.to_string()),
                ("r", self.r.to_string()),
                ("p", self.p.to_string()),
            ]
        }

        fn hash_id(&self) -> Hashes {
            Hashes::Scrypt
        }
    }

    impl fmt::Debug for Scrypt {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            write!(
                f,
                "Scrypt, N: {}, r: {}, p: {}",
                1 << self.log_n,
                self.r,
                self.p
            )
        }
    }

    impl Scrypt {
        /// Gets the default scrypt instance.
        pub fn default() -> Primitive {
            Primitive(Sod::Static(&*DEFAULT))
        }

        fn new_impl(log_n: u8, r: u32, p: u32) -> Self {
            Self {
                log_n,
                r,
                p,
                params: scrypt::Params::new(log_n, r, p).expect("invalid scrypt parameters"),
            }
        }

        /// Create  a new scrypt instance.
        #[allow(clippy::new_ret_no_self)]
        pub fn new(log_n: u8, r: u32, p: u32) -> Primitive {
            Self::new_impl(log_n, r, p).into()
        }
    }
}

#[cfg(test)]
mod test {
    use data_encoding;
    use hashing::*;
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
            alg: Algorithm::Single(params),
            salt,
            hash,
        };
        println!("{:?}", serde_mcf::to_string(&out).unwrap());
    }

    fn scrypt_test(
        password: &str,
        salt: &str,
        n: u32,
        r: u32,
        p: u32,
        _output_len: u32,
        expected: &str,
    ) {
        let scrypt = super::Scrypt::new(f32::log2(n as f32) as u8, r, p);
        let hash = scrypt.compute(password.as_bytes(), salt.as_bytes());
        let expected = expected.replace(" ", "");
        println!("{}", expected);
        let expected = data_encoding::HEXLOWER.decode(expected.as_bytes()).unwrap();
        assert_eq!(&expected[..32], &hash[..]);
    }

    #[test]
    fn scrypt_test_vectors() {
        scrypt_test(
            "",
            "",
            16,
            1,
            1,
            64,
            "\
        77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97\
        f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42\
        fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17\
        e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06",
        );

        scrypt_test(
            "password",
            "NaCl",
            1024,
            8,
            16,
            64,
            "\
        fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe\
        7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62\
        2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da\
        c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40",
        );
    }

    #[test]
    #[cfg(feature = "long_tests")]
    fn scrypt_test_vectors_long() {
        scrypt_test(
            "pleaseletmein",
            "SodiumChloride",
            16384,
            8,
            1,
            64,
            "\
        70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb\
        fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2\
        d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9\
        e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87",
        );
        scrypt_test(
            "pleaseletmein",
            "SodiumChloride",
            1048576,
            8,
            1,
            64,
            "\
        21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81\
        ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47\
        8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3\
        37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4",
        );
    }
}

benches!(Scrypt);
