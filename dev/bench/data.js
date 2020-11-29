window.BENCHMARK_DATA = {
  "lastUpdate": 1606687104281,
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
      },
      {
        "commit": {
          "author": {
            "email": "sam@osohq.com",
            "name": "Sam Scott",
            "username": "samscott89"
          },
          "committer": {
            "email": "sam@osohq.com",
            "name": "Sam Scott",
            "username": "samscott89"
          },
          "distinct": true,
          "id": "3ad996fbc7998e3017051a1b59e727006bf58ac9",
          "message": "Update README.",
          "timestamp": "2020-11-29T16:46:21-05:00",
          "tree_id": "ffd2d8b595ab8c81cfa48fafdf1a7631f76ef150",
          "url": "https://github.com/libpasta/libpasta/commit/3ad996fbc7998e3017051a1b59e727006bf58ac9"
        },
        "date": 1606687103427,
        "tool": "cargo",
        "benches": [
          {
            "name": "pasta_hash",
            "value": 69471229,
            "range": "± 4144797",
            "unit": "ns/iter"
          },
          {
            "name": "pasta_hash_dyn_alg",
            "value": 68674805,
            "range": "± 3640681",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/native_1",
            "value": 2860595,
            "range": "± 126688",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/native_4",
            "value": 2385612,
            "range": "± 88992",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/ffi_1",
            "value": 2638763,
            "range": "± 105984",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/ffi_4",
            "value": 3120916,
            "range": "± 284687",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/pasta_1",
            "value": 2702820,
            "range": "± 120760",
            "unit": "ns/iter"
          },
          {
            "name": "argon2/pasta_4",
            "value": 2372831,
            "range": "± 96698",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}