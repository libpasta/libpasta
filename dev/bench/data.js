window.BENCHMARK_DATA = {
  "lastUpdate": 1606681905121,
  "repoUrl": "https://github.com/libpasta/libpasta",
  "entries": {
    "Rust Benchmark": [
      {
        "commit": {
          "author": {
            "email": "sam@osohq.com",
            "name": "Sam Scott",
            "username": "samscott89"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "da15f56bcbac9c2247a199a3aceb6d41b5f7e76d",
          "message": "Formatting, cleanup, update benchmarking code. (#13)",
          "timestamp": "2020-11-29T15:22:08-05:00",
          "tree_id": "c849d309417be1c4d482eadd35ee864f87273eb1",
          "url": "https://github.com/libpasta/libpasta/commit/da15f56bcbac9c2247a199a3aceb6d41b5f7e76d"
        },
        "date": 1606681903470,
        "tool": "cargo",
        "benches": [
          {
            "name": "pasta_hash",
            "value": 66893034,
            "range": "± 834676",
            "unit": "ns/iter"
          },
          {
            "name": "pasta_hash_dyn_alg",
            "value": 66193010,
            "range": "± 786911",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/native_1",
            "value": 2535415,
            "range": "± 2113",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/native_4",
            "value": 2241511,
            "range": "± 61874",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/ffi_1",
            "value": 2336749,
            "range": "± 42626",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/ffi_4",
            "value": 3387355,
            "range": "± 79983",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/pasta_1",
            "value": 2537987,
            "range": "± 3007",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/pasta_4",
            "value": 2246733,
            "range": "± 41565",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}