pub use self::native::Bcrypt;

mod native {
    #![allow(shadow_reuse)]

    extern crate crypto;
    use self::crypto::bcrypt::bcrypt;

    use primitives::{Primitive, PrimitiveImpl};
    use primitives::sod::Sod;

    use serde_mcf::Hashes;

    use std::fmt;
    use std::sync::Arc;

    /// `bcrypt` parameter set.
    ///
    /// Holds the cost value.
    /// This implementation is backed by `rust-crypto`.
    #[derive(Clone, Deserialize, Serialize)]
    pub struct Bcrypt {
        cost: u32,
    }

    lazy_static! {
        static ref DEFAULT: Arc<Box<PrimitiveImpl>> = {
            Arc::new(Box::new(Bcrypt::new_impl(12)))
        };
    }

    impl PrimitiveImpl for Bcrypt {
        fn compute<'a>(&'a self, password: &[u8], salt: &[u8]) -> Vec<u8> {
            let mut hash = [0_u8; 24];
            let mut pw = [0_u8; 72];
            // Bcrypt inputs need to be at most 72 bytes
            // with a trailing zero byte only if < 72 bytes
            let pw = if password.len() > 71 {
                pw[..72].copy_from_slice(&password[..72]);
                &pw[..]
            } else {
                pw[..password.len()].copy_from_slice(password);
                &pw[..password.len() + 1]
            };
            bcrypt(self.cost, salt, pw, &mut hash);
            hash[..23].to_vec()
        }

        fn params_as_vec(&self) -> Vec<(&'static str, String)> {
            vec![("cost", self.cost.to_string())]
        }

        fn hash_id(&self) -> Hashes {
            Hashes::BcryptMcf
        }
    }


    impl fmt::Debug for Bcrypt {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            write!(f, "Bcrypt, cost: {:?}", self.cost)
        }
    }

    impl Bcrypt {
        /// Construct a new `Bcrypt` parameter set.
        pub fn new(cost: u32) -> Primitive {
            Self::new_impl(cost).into()
        }

        fn new_impl(cost: u32) -> Self {
            Self { cost: cost }.into()
        }

        /// Get the default `Bcrypt` parameter set.
        pub fn default() -> Primitive {
            Primitive(Sod::Dynamic((*DEFAULT).clone()))
        }
    }
}

benches!(Bcrypt);

#[cfg(test)]
mod bcrypt_test {
    use hashing::*;
    use serde_mcf as mcf;

    #[test]
    fn sanity_check() {
        let password = "hunter2";
        let params = super::Bcrypt::default();
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
        println!("{:?}", mcf::to_string(&out).unwrap());
    }

    #[test]
    fn verifies_bcrypt_hashes() {
        let password = "hunter2".to_owned();
        let hash = "$2a$10$ckjEeyTD6estWyoofn4EROM9Ik2PqVcfcrepX.uGp6.aqRdCMN/Oe";
        assert!(::verify_password(&hash, password));
    }

    fn openwall_test(hash: &str, password: &[u8]) {
        let pwd_hash: Output = mcf::from_str(&hash).unwrap();
        assert_eq!(pwd_hash.hash,
                   pwd_hash.alg.hash_with_salt(password, &pwd_hash.salt));
    }

    // Test the internal Bcrypt implementation against the openwall test vectors.
    // Note that we currently are non compatible with "2x" variant hashes.
    #[test]
    fn openwall_test_vectors() {
        openwall_test("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
                      b"U*U");
        openwall_test("$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
                      b"U*U*");
        openwall_test("$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
                      b"U*U*U");
        openwall_test("$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
                      b"");
        openwall_test("$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
                      b"0123456789abcdefghijklmnopqrstuvwxyz\
             ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\
             chars after 72 are ignored");
        // openwall_test("$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e", b"\xa3");
        openwall_test("$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq",
                      b"\xa3");
        // openwall_test("$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS", b"\xd1\x91");
        // openwall_test("$2x$05$6bNw2HLQYeqHYyBfLMsv/O9LIGgn8OMzuDoHfof8AQimSGfcSWxnS", b"\xd0\xc1\xd2\xcf\xcc\xd8");
        openwall_test("$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6",
                      b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
             \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
             \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
             \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
             \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
             \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
             chars after 72 are ignored as usual");
        openwall_test("$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy",
                      b"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\
              \xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\
              \xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\
              \xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\
              \xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\
              \xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55");
        openwall_test("$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
                      b"");
        openwall_test("$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe",
                      b"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\
              \x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\
              \x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\
              \x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\
              \x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\
              \x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff");
    }
}
