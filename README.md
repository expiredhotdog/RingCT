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
| 2           | 0.509       | 0.334       | 160          |
| 4           | 0.943       | 0.618       | 224          |
| 8           | 1.588       | 1.183       | 352          |
| 16          | 3.331       | 2.319       | 608          |
| 32          | 6.907       | 4.597       | 1120         |
| 64          | 11.75       | 9.159       | 2144         |
| 128         | 23.26       | 18.26       | 4192         |
| 256         | 48.03       | 36.59       | 8288         |
| 512         | 108.8       | 73.16       | 16480        |
| 1024        | 195.4       | 145.3       | 32864        |

### MLSAG

| ringsize    | sign (ms)   | verify (ms) | size (bytes) |
| ----------- | ----------- | ----------- | ------------ |
| 2           | 0.441       | 0.289       | 192          |
| 4           | 0.865       | 0.572       | 320          |
| 8           | 1.476       | 1.131       | 576          |
| 16          | 3.071       | 2.263       | 1088         |
| 32          | 6.685       | 4.528       | 2112         |
| 64          | 11.72       | 9.037       | 4160         |
| 128         | 26.23       | 18.08       | 8256         |
| 256         | 46.21       | 36.15       | 16448        |
| 512         | 105.9       | 72.27       | 32832        |
| 1024        | 201.6       | 144.9       | 65600        |

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
| 7.737       | 5.969       | 5120         |

## ECDH

| shared secret (ns) | view tag (ns) | derive private key (ns) |
| ------------------ | ------------- | ----------------------- |
| 44785              | 259           | 124                     |


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
