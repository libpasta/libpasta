#[doc(hidden)]
#[macro_export]
macro_rules! benches {
    ($params:path) => {
        #[cfg(all(test, feature="bench"))]
        mod bench {
            #![allow(unused_qualifications, unused_imports)]
            extern crate test;

            use self::test::Bencher;

            use super::*;

            use ::hashing::Algorithm;

            #[bench]
            fn short(b: &mut Bencher) {
                let password = "hunter2*********";
                let alg = Algorithm::Single(<$params>::default().into());
                println!("Bench params: {:?}", alg);
                b.iter(|| {
                    alg.hash(password)
                })
            }

            #[bench]
            fn long(b: &mut Bencher) {
                let password = "hunter2".to_owned().repeat(10);
                println!("Password: {:?}", &password);
                let alg = Algorithm::Single(<$params>::default().into());
                println!("Bench params: {:?}", alg);
                b.iter(|| {
                    alg.hash(&password)
                })
            }
        }

    }
}
