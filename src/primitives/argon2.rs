pub use self::native::Argon2;

mod native {
    extern crate argon2rs;

    use primitives::Primitive;
    use sod::Sod;

    use serde_mcf::Hashes;

    use std::fmt;

    /// Parameter set for Argon2.
    ///
    /// This implementation is backed by the `argon2rs` crate.
    pub struct Argon2 {
        algorithm: argon2rs::Argon2,
    }

    impl ::primitives::PrimitiveImpl for Argon2 {
        fn compute<'a>(&'a self, password: &[u8], salt: &[u8]) -> Vec<u8> {
            let mut hash = [0_u8; 32];
            self.algorithm.hash(&mut hash, password, salt, &[], &[]);
            hash.to_vec()
        }

        fn params_as_vec(&self) -> Vec<(&'static str, String)> {
            let (_, kib, passes, lanes) = self.algorithm.params();
            vec![("m", kib.to_string()), ("t", passes.to_string()), ("p", lanes.to_string())]
        }

        fn hash_id(&self) -> Hashes {
            Hashes::Argon2i
        }
    }

    lazy_static! {
        pub static ref DEFAULT: Argon2 = {
            Argon2 {
                algorithm: argon2rs::Argon2::default(argon2rs::Variant::Argon2i)
            }
        };
    }

    impl Argon2 {
        /// Get the default Argon2i parameter set
        pub fn default() -> Primitive {
            Primitive(Sod::Static(&*DEFAULT))
        }

        fn new_impl(passes: u32, lanes: u32, kib: u32) -> Self {
            Self {
                algorithm: argon2rs::Argon2::new(passes, lanes, kib, argon2rs::Variant::Argon2i)
                    .expect("invalid Argon2 parameters"),
            }
        }

        /// Creates a new Argon2i instance
        pub fn new(passes: u32, lanes: u32, kib: u32) -> Primitive {
            Self::new_impl(passes, lanes, kib).into()
        }
    }

    impl fmt::Debug for Argon2 {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            write!(f, "Argon2i: {:?}", self.algorithm.params())
        }
    }
}


benches!(Argon2);

#[cfg(test)]
mod test {
    use data_encoding::HEXLOWER;
    use serde_mcf;
    use super::*;
    use hashing::*;

    #[test]
    fn sanity_check() {
        let password = "hunter2";
        let params = super::Argon2::default();
        println!("{:?}", params);
        let salt = ::get_salt();
        let hash = params.compute(password.as_bytes(), &salt);
        let hash2 = params.compute(password.as_bytes(), &salt);
        assert_eq!(hash, hash2);
        let out = Output {
            alg: Algorithm::Single(params.into()),
            salt,
            hash,
        };
        println!("{:?}", serde_mcf::to_string(&out).unwrap());
    }

    fn hashtest(passes: u32,
                m: u32,
                lanes: u32,
                password: &str,
                salt: &str,
                hexpected: &str,
                encoded: &str) {
        let alg = Argon2::new(passes, lanes, 1 << m);
        let hash = alg.compute(password.as_bytes(), salt.as_bytes());
        assert_eq!(HEXLOWER.encode(&hash), hexpected);
        assert_eq!(serde_mcf::from_str::<Output>(encoded).unwrap().hash, hash);
        let output = Output {
            alg: Algorithm::Single(alg.into()),
            hash,
            salt: salt.as_bytes().to_vec(),
        };
        assert_eq!(&serde_mcf::to_string(&output).unwrap()[1..], encoded);
    }

    #[test]
    fn argon2i_ref_tests() {
        hashtest(2,
                 8,
                 1,
                 "password",
                 "somesalt",
                 "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
                 "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ\
                 $/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY");
        hashtest(2,
                 8,
                 2,
                 "password",
                 "somesalt",
                 "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
                 "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ\
                 $tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs");
        hashtest(1,
                 16,
                 1,
                 "password",
                 "somesalt",
                 "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
                 "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ\
                 $gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI");
        hashtest(4,
                 16,
                 1,
                 "password",
                 "somesalt",
                 "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
                 "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ\
                 $8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs");
        hashtest(2,
                 16,
                 1,
                 "differentpassword",
                 "somesalt",
                 "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
                 "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ\
                 $6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM");
        hashtest(2,
                 16,
                 1,
                 "password",
                 "diffsalt",
                 "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
                 "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ\
                 $eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc");
    }

    #[test] #[cfg(feature = "long_tests")]
    fn argon2i_ref_tests() {
        hashtest(2,
                 18,
                 1,
                 "password",
                 "somesalt",
                 "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
                 "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ\
                 $Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc");
    }
}
