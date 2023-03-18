# RingCT

A fast, stable, pure-Rust implementation of Ring Confidential Transactions (RingCT) using Ristretto.

This library does not implement a full transaction protocol, only low/mid-level APIs for use in experimentation or a larger project.
Also note that this is an independent implementation, and is not currently designed to work with other implementations such as Monero's.

This implementation has **not** been formally audited. **Use at your own risk**.

# Features

Core RingCT protocols are implemented by this crate.

* Pedersen commitments
* Ring signatures
    * MLSAG (historical)
    * CLSAG
* Rangeproofs
    * Borromean ring signature-based (historical)
    * Bulletproofs+
        * Proof aggregation
        * Batch verification
* ECDH & Stealth Addresses
    * CryptoNote-like addresses
    * Monero-like Subaddresses
    * Custom address protocols

# Usage

Usage examples can be found in the `examples` folder within this repository.

# Performance

All benchmarks were run on an i5-9600k.
Most times are listed in milliseconds (ms), though some are in nanoseconds (ns).

## Ring Signatures

### CLSAG

| ringsize    |  sign (ms)  | verify (ms) | size (bytes) |
| ----------- | ----------- | ----------- | ------------ |
| 2           | 0.506       | 0.330       | 160          |
| 4           | 0.865       | 0.619       | 224          |
| 8           | 1.682       | 1.170       | 352          |
| 16          | 3.177       | 2.305       | 608          |
| 32          | 6.578       | 4.565       | 1120         |
| 64          | 12.64       | 9.087       | 2144         |
| 128         | 24.60       | 18.16       | 4192         |
| 256         | 54.26       | 36.43       | 8288         |
| 512         | 107.5       | 72.35       | 16480        |
| 1024        | 188.6       | 144.1       | 32864        |

### MLSAG

| ringsize    | sign (ms)   | verify (ms) | size (bytes) |
| ----------- | ----------- | ----------- | ------------ |
| 2           | 0.407       | 0.288       | 192          |
| 4           | 0.868       | 0.566       | 320          |
| 8           | 1.473       | 1.128       | 576          |
| 16          | 3.359       | 2.262       | 1088         |
| 32          | 5.994       | 4.520       | 2112         |
| 64          | 13.59       | 9.038       | 4160         |
| 128         | 24.79       | 18.05       | 8256         |
| 256         | 45.50       | 36.10       | 16448        |
| 512         | 99.50       | 72.21       | 32832        |
| 1024        | 199.9       | 145.0       | 65600        |

## Rangeproofs

All rangeproofs are 64-bit.

### Bulletproofs+

Note that batch verification times are per-proof, not for the entire batch.

| Aggregation Size | prove (ms) | verify (ms)  | batch verify, 25 (ms) | batch verify, 256 (ms) | size (bytes) |
| ---------------- | ---------- | ------------ | --------------------- | ---------------------- | ------------ |
| 1                | 14.051     | 1.436        | 0.356                 | 0.305                  | 576          |
| 2                | 27.291     | 2.552        | 0.531                 | 0.467                  | 640          |
| 4                | 53.380     | 4.239        | 0.865                 | 0.768                  | 704          |
| 8                | 104.47     | 7.536        | 1.528                 | 1.360                  | 768          |
| 16               | 203.80     | 14.03        | 2.859                 | 2.544                  | 832          |
| 128              | 1599.6     | 106.4        | 21.84                 | 19.61                  | 1024         |

### Borromean

| prove (ms)  | verify (ms) | size (bytes) |
| ----------- | ----------- | ------------ |
| 7.687       | 5.900       | 5120         |

## ECDH

| shared secret (ns) | view tag (ns) | derive private key (ns) |
| ------------------ | ------------- | ----------------------- |
| 44501              | 152           | 104                     |


# Licensing

The core library code is licensed under the Mozilla Public License v2.0,
a copy of which can be found at [this link](https://mozilla.org/MPL/2.0/)
or in this repository at `LICENSE-MPL`.
Everything else that is part of this crate, excluding any dependencies,
and including but not limited to tests, examples, and benchmarks, is licensed under the Unlicense,
a copy of which can be found at [this link](https://unlicense.org/)
or in this repository at `LICENSE-UNLICENSE`.

# Roadmap

These are things which **might** be supported in the future. No guarantees.

* ElGamal commitments
* Bulletproofs++
* Generalized CLSAG & MLSAG implementations (currently they are specifically tailored to RingCT)
* Alternative elliptic curves & improved configurability
* Multisig

# Credits

This library makes use of
[Tari's Bulletproofs+ implementation](https://github.com/tari-project/bulletproofs-plus).
