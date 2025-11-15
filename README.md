# openfhe-go - unofficial Go wrapper for OpenFHE C++

Target: OpenFHE v1.4.2

## Features

### Supported Schemes
- **CKKS**: Approximate arithmetic on encrypted real/complex numbers
- **BFV**: Exact arithmetic on encrypted integers
- **BGV**: Exact arithmetic on encrypted integers (SIMD)
- **BinFHE**: Boolean operations on encrypted bits
- **Scheme Switching**: Switch between CKKS and FHEW for hybrid operations

### Advanced Operations
- **Proxy Re-Encryption (PRE)**: Delegate decryption rights without revealing keys
- **Comparison Operations**: Find min/max values and argmin/argmax indices via scheme switching
- **Bootstrapping**: CKKS and BinFHE bootstrapping for unlimited depth computations

## Build

```
make build
```

## Run tests

```
make test
```

## Run examples

```
make run-examples
```

See examples and tests for usage

## Examples

### Boolean FHE
- [ ] boolean-ap
- [ ] boolean-lmkcdey
- [x] boolean-truth-tables
- [x] boolean

### PKE FHE
- [x] advanced-real-numbers-128
- [x] advanced-real-numbers
- [x] comparison-argmin (min/max with argmin/argmax via scheme switching)
- [ ] function-evaluation
- [x] inner-product
- [ ] interactive-bootstrapping
- [ ] iterative-ckks-bootstrapping
- [x] plaintext-operations
- [x] polynomial-evaluation
- [x] pre-buffer
- [x] scheme-switching
- [x] simple-ckks-bootstrapping
- [x] simple-integers-bgvrns
- [ ] simple-integers-serial-bgvrns
- [x] simple-integers-serial
- [x] simple-integers
- [x] simple-real-numbers-serial
- [x] simple-real-numbers
- [ ] tckks-interactive-mp-bootstrapping-Chebyschev
- [ ] tckks-interactive-mp-bootstrapping
- [ ] threshold-fhe-5p
- [ ] threshold-fhe

## Links

* https://openfhe.org/
* https://github.com/openfheorg/openfhe-development
