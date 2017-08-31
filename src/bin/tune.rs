extern crate argon2rs;
#[macro_use]
extern crate clap;
extern crate libpasta;
extern crate optimization;
extern crate sys_info;
extern crate time;

use clap::Arg;

use libpasta::config;
use libpasta::primitives::{Argon2, Bcrypt, Scrypt};
use libpasta::primitives::Primitive;

fn main() {
    let mut app = clap_app!(tune =>
        (version: "0.0.1")
        (author: "Sam Scott")
        (about: "libpasta tuning tool")
        (@arg target:    -t --target    +takes_value "Set the target number of verifications per second to support (defaut: 2)")
        (@arg verbose:   -v --verbose   ...          "Print test information verbosely")
        (@arg printconfig: -p --print                "Output the final result in the configuration file format")
    );

    app = app.arg(Arg::with_name("algorithm")
        .short("a")
        .long("algorithm")
        .takes_value(true)
        .possible_values(&["argon2i", "bcrypt", "scrypt"])
        .help("Choose the algorithm to tune (default: argon2i)"));

    let m = app.get_matches();

    let alg = m.value_of("algorithm").unwrap_or("argon2i");
    let t = m.value_of("target").unwrap_or("2.0");
    let target = t.parse::<f64>().expect("Please provide a numeric value for target");

    let prim = match alg {
        "argon2i" => tune_argon(target),
        "bcrypt" => tune_bcrypt(target),
        "scrypt" => tune_scrypt(target),
        _ => {
            panic!("Unsupported variant");
        }
    };

    config::set_primitive(prim);
    if m.is_present("printconfig") {
        print!("\nAlgorithm in configuration format:\n");
        println!("{}", config::to_string());
    }
}

fn tune_argon(target: f64) -> Primitive {
    let (_, rec_kib, rec_pass, rec_lanes) = argon2rs::Argon2::default(argon2rs::Variant::Argon2i)
        .params();
    let repetitions = 10u8;
    let meminfo = sys_info::mem_info().unwrap();
    let cpunum = sys_info::cpu_num().unwrap();
    let timelimit = 1_000_000_000f64 / target as f64;

    // By default attempt to use at most 12.5% of system memory
    let max_memory = (meminfo.total >> 3) as u32;
    let mut memory = 1 << 4;


    // let memory = 1<<14; // 16MiB
    // Use all the CPUs, up to maximum of 8.
    // let lanes = std::cmp::min(8, cpunum);
    let mut elapsed = 0f64;

    while elapsed < timelimit {
        memory <<= 1;
        if memory > max_memory {
            break;
        }
        let alg = Argon2::new(rec_pass, rec_lanes, memory);
        let password = "hunter2".to_owned();
        let salt = b"thisisagreatsalt";
        let start = time::precise_time_ns();
        for _ in 0..repetitions {
            alg.compute(password.as_bytes(), salt);
        }
        let end = time::precise_time_ns();
        elapsed = (end - start) as f64 / repetitions as f64;
        println!("passes = {}, threads = {}, memory = {} {:.4} s",
                 3,
                 1,
                 memory,
                 elapsed / 1_000_000_000f64);
    }
    memory >>= 1;

    println!("Maximum amount of memory (capped at {:.0}) to achieve < {:.2} s hash = {} KiB",
             max_memory,
             timelimit / 1_000_000_000f64,
             memory);
    if memory < rec_kib {
        println!("Unable to reach minimum recommended parameters for requested timeframe. \
                  Falling back to defaults.");
        memory = rec_kib;
    }


    let mut passes;


    let mut highest_passes = 1;
    let mut best_lanes = 1;

    // Intentionally use at most N-1 CPUs to avoid consuming system.
    for lanes in 1..cpunum {
        elapsed = 0f64;
        passes = highest_passes + 1;
        while elapsed < timelimit {
            let alg = Argon2::new(passes, lanes, memory);
            let password = "hunter2".to_owned();
            let salt = b"thisisagreatsalt";
            let start = time::precise_time_ns();
            for _ in 0..repetitions {
                alg.compute(password.as_bytes(), salt);
            }
            let end = time::precise_time_ns();
            elapsed = (end - start) as f64 / repetitions as f64;
            println!("passes = {:2}, threads = {}, memory = {} {:.4} s",
                     passes,
                     lanes,
                     memory,
                     elapsed / 1_000_000_000f64);
            if elapsed < timelimit {
                highest_passes = passes;
                best_lanes = lanes;
            }
            passes += 1;

        }

    }

    if highest_passes < rec_pass {
        println!("Unable to reach minimum recommended parameters for requested timeframe. \
                  Falling back to defaults.");
        highest_passes = rec_pass;
    }


    println!("Recommended: {:?}",
             Argon2::new(highest_passes, best_lanes, memory));
    println!("Default:     {:?}", Argon2::default());

    Argon2::new(highest_passes, best_lanes, memory)
}

fn tune_scrypt(target: f64) -> Primitive {

    let cpu_speed = sys_info::cpu_speed().unwrap();
    println!("CPU speed: {:?}", cpu_speed);
    let cpu_speed = cpu_speed as f64 * 1_000_000f64;
    #[inline(always)]
    fn memcost(log_n: u8, r: u32, p: u32) -> u32 {
        // 128 * N * r + 128 * r * p memory
        (128 * (1 << log_n) * r + 128 * r * p) / 1024
    }

    #[inline(always)]
    fn timecost(log_n: u8, r: u32, _p: u32) -> f64 {
        // Takes 4*N applications of Salsa20/8
        // with input size 128*r
        ( 4.0 * (1<<log_n) as f64 )
        // Lower bound for Salsa20/8 is 2 cycles/byte
        // ROMix uses 128 * r byte blocks
        * (2.28 * 128.0 * r as f64)
    }


    let (rec_nlog, _rec_r, _rec_p) = (14, 8, 1);

    let repetitions = 10u8;
    let meminfo = sys_info::mem_info().unwrap();
    let cpunum = sys_info::cpu_num().unwrap();
    let timelimit = 1_000_000_000f64 / target as f64;

    let mut n = 10;
    while timecost(n, 8, 1) < cpu_speed / target {
        n += 1;
    }
    n -= 1;
    println!("Predicted maximum parameter: {:?}, with time: {:.3}s",
             n,
             timecost(n, 8, 1) / cpu_speed);

    // By default attempt to use at most 12.5% of system memory
    let max_memory = (meminfo.total >> 3) as u32;
    let mut memory = 4;
    let mut p = 1;
    let r = 8;
    let mut highest_mem = memory;
    let mut highest_p = p;
    let mut elapsed;

    loop {
        elapsed = 0f64;
        if p > cpunum {
            break;
        }
        while elapsed < timelimit {
            memory += 1;
            if memcost(memory, r, p) > max_memory {
                break;
            }
            let alg = Scrypt::new(memory, r, p);
            let password = "hunter2".to_owned();
            let salt = b"thisisagreatsalt";
            let start = time::precise_time_ns();
            for _ in 0..repetitions {
                alg.compute(password.as_bytes(), salt);
            }
            let end = time::precise_time_ns();
            elapsed = (end - start) as f64 / repetitions as f64;
            println!("logN = {}, parallel = {}, read size = {} ~> memory = {} KiB {:.4} s \
                      (estimated: {:.4} s)",
                     memory,
                     p,
                     r,
                     memcost(memory, r, p),
                     elapsed / 1_000_000_000f64,
                     timecost(memory, r, p) / cpu_speed);
            if elapsed < timelimit {
                highest_p = p;
                highest_mem = memory;
            }
        }
        memory -= 1;
        p <<= 1;
    }

    println!("Maximum amount of memory (capped at {:.0} KiB) to achieve < {:.2} s hash = {} KiB",
             max_memory,
             timelimit / 1_000_000_000f64,
             memcost(memory, r, p));
    if highest_mem < rec_nlog {
        println!("Unable to reach minimum recommended parameters for requested timeframe. \
                  Falling back to defaults.");
        highest_mem = rec_nlog;
        highest_p = 1;
    }

    println!("Recommended: {:?}", Scrypt::new(highest_mem, r, highest_p));
    println!("Default:     {:?}", Scrypt::default());

    Scrypt::new(highest_mem, r, highest_p)
}


fn tune_bcrypt(target: f64) -> Primitive {
    let timelimit = 1_000_000_000f64 / target as f64;

    let mut elapsed = 0f64;
    let rec_cost = 12;
    let mut cost = 6;
    let repetitions = 100;

    while elapsed < timelimit {
        let alg = Bcrypt::new(cost);
        let password = "hunter2".to_owned();
        let salt = b"thisisagreatsalt";
        let start = time::precise_time_ns();
        for _ in 0..repetitions {
            alg.compute(password.as_bytes(), salt);
        }
        let end = time::precise_time_ns();
        elapsed = (end - start) as f64 / repetitions as f64;
        println!("{:.4} s", elapsed / 1_000_000_000f64);
        cost += 1;
    }

    if cost < rec_cost {
        println!("Unable to reach minimum recommended parameters for requested timeframe. \
                  Falling back to defaults.");
        cost = rec_cost;
    }

    println!("Recommended: {:?}", Bcrypt::new(cost));
    println!("Default:     {:?}", Bcrypt::default());

    Bcrypt::new(cost)
}


pub use cost::estimate_cost;
mod cost {
    use optimization::{Minimizer, GradientDescent, NumericalDifferentiation, Func};

    use std::f64;

    /// Approximate energy consumption for computation for a CPU.
    ///
    /// This value is approximately the joules per cycle, scaled using
    /// https://www.cryptopp.com/benchmarks.html and
    /// https://eprint.iacr.org/2017/225.pdf
    /// SHA256 30nJ/B and 13.4 cycles/B
    /// AES-NI 1.5nJ/B and 0.8 cycles/B
    /// Works out as appoximately 2.19nJ/cycle.
    const T_CPU: f64 = (30.0 / 13.4 + 1.5 / 0.7) / 2.0;
    /// Approximate energy consumption per byte for memory access;
    ///
    /// Using https://eprint.iacr.org/2017/225.pdf (which links other sources).
    const M_CPU: f64 = 0.5;
    /// Approximate energy consumption for computation for a well-designed ASIC.
    /// Similarly scaled to match an approximate "cycle" of computation.
    ///
    /// Computed from: https://eprint.iacr.org/2017/225.pdf which in turn
    /// cites the power usage of AntMiner C9.
    // const T_ASIC: f64 = 0.0012 / 13.4;
    const T_ASIC: f64 = 0.0053 / 4.5;
    // const T_ASIC: f64 = 0.02;

    /// Approximate energy consumption per byte for an ASIC.
    /// We do not actually use this constant value, in exchange for one which
    /// scales to account for larger memory consuming more energy.
    ///
    /// Roughly based off of https://eprint.iacr.org/2017/225.pdf
    #[allow(dead_code)]
    const M_ASIC: f64 = 0.3;

    pub fn estimate_cost<F>(cycles: f64, mem: f64, tm_tradeoff: F) -> (f64, f64)
        where F: Fn(f64, f64, f64) -> (f64, f64)
    {
        let cost_fn = NumericalDifferentiation::new(Func(|x: &[f64]| {
            let (ta_cycles, ta_mem) = tm_tradeoff(cycles, mem, x[0]);
            t_asic(ta_cycles) + m_asic(ta_mem)
        }));

        let minimizer = GradientDescent::new();
        let solution = minimizer.minimize(&cost_fn, vec![1f64]);

        ((t_cpu(cycles) + m_cpu(mem)), solution.value)
    }

    fn t_cpu(cycles: f64) -> f64 {
        T_CPU * cycles as f64
    }
    fn m_cpu(mem: f64) -> f64 {
        M_CPU * mem as f64
    }
    fn t_asic(cycles: f64) -> f64 {
        T_ASIC * cycles as f64
    }
    fn m_asic(mem: f64) -> f64 {
        let m_asic = match mem {
            x if x < (1 << 19) as f64 => (mem / (1u32 << 13) as f64).sqrt() / 1000.0,
            x if x < (1 << 23) as f64 => 0.0125,
            _ => 0.2,
        };
        m_asic * mem
    }

    #[allow(dead_code)]
    pub fn scrypt_cost_fn(cx: f64, mx: f64, scale: f64) -> (f64, f64) {
        if scale < 1.0 || scale > cx {
            (f64::MAX, f64::MAX)
        } else {

            let retval = (cx * (scale + 1.0) / 2.0, mx / scale);
            // println!("{:?}", retval);
            retval
        }
    }

    #[test]
    fn test_cost_estimate() {
        // https://eprint.iacr.org/2016/115.pdf

        let tolerance = 0.1;
        // 8KB costs about 1pJ per byte
        assert!(f64::abs(m_asic((1 << 13) as f64) / (1 << 13) as f64 - 0.001) / 0.001 < tolerance);
        // 1MB costs about 12.5pJ per byte
        assert!(f64::abs(m_asic((1 << 20) as f64) / (1 << 20) as f64 - 0.0125) / 0.0125 <
                tolerance);
        // For larger amount ~1GB we get 200J/ per byte
        assert_eq!(m_asic((1 << 30) as f64), 0.2 * (1 << 30) as f64);

        // SHA256 numbers
        let (cpu, asic) = estimate_cost(13.4, 0.0, |cx, mx, _| (cx, mx));
        assert!(cpu > 100.0 * asic);

        // Scrypt numbers with params n
        let n = (1u32 << 20) as f64;
        let r = 8.0;
        let p = 1.0;
        // 3.3 as the scrypt cycles/byte cost factor for computation.
        let cycles = 3.3 * (4.0 * n * r);
        let mem = 128.0 * n * r + 128.0 * r * p;

        let (cpu, asic) = estimate_cost(cycles, mem, scrypt_cost_fn);

        println!("Estimates: CPU={}, ASIC(opt)={}, ASIC(naive):{}",
                 cpu,
                 asic,
                 t_asic(cycles) + m_asic(mem));
        println!("Breakdown:\n\tt_cpu =  {:15.2}\n\tt_asic = {:15.2}\n\tm_cpu =  \
                  {:15.2}\n\tm_asic = {:15.2}",
                 t_cpu(cycles),
                 t_asic(cycles),
                 m_cpu(mem),
                 m_asic(mem));
        assert!(cpu > 2.0 * asic);


        // Argon2i numbers
        // https://iis-people.ee.ethz.ch/~sha3/

        // Power of Blake(2b?): 6.62pJ/bit -> ~53pJ/byte
        // From cryptopp benchmarks, 4.6 cycles per byte
        // let n = ()

    }
}
