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
- **Function Evaluation**: Evaluate arbitrary smooth functions on encrypted data using Chebyshev approximation
  - Pre-defined functions: `EvalLogistic`, `EvalSin`, `EvalCos`, `EvalDivide`
  - Custom functions: `EvalChebyshevFunction` with Go callbacks (any `func(float64) float64`)
  - Batch optimization: `EvalChebyshevCoefficients` + `EvalChebyshevSeries` for reusing coefficients

## Build

### Quick Start

```bash
# Development build (fast, uses shared libraries)
make build

# Production build (static binary, slower)
make build-static
```

### Build Details

The project supports two build modes:

#### Development Mode (Default - Shared Libraries)
Fast iteration with shared libraries - ideal for development and testing.

```bash
make build          # Build with shared libraries
make test           # Run tests
make run-examples   # Run all examples
```

**Build times:**
- **First-time OpenFHE build**: 3-5 minutes (builds C++ OpenFHE library)
- **Subsequent Go builds**: 5-30 seconds (recompiles C++ wrappers, links against shared libs)
- **OpenFHE only**: `make build_openfhe` (builds shared libraries only)

The C++ wrapper files are recompiled by CGO on each build, but linking against shared libraries is much faster than static linking.

#### Production Mode (Static Libraries)
Standalone binaries with statically linked OpenFHE - ideal for deployment.

```bash
make build-static    # Build with static libraries
```

**Build times:**
- **First-time static build**: 3-5 minutes (builds C++ OpenFHE static libraries)
- **Subsequent static builds**: 30-120 seconds (relinks all static `.a` files)
- **Static libs only**: `make build_openfhe_static`

Static builds produce self-contained binaries but are slower due to relinking all libraries on each build.

### Switching Between Build Modes

To switch from one mode to another, clean the OpenFHE installation:

```bash
make clean_openfhe   # Remove OpenFHE build artifacts
make build           # Rebuild with desired mode
```

### Build Requirements

The Makefile automatically handles:
- Cloning OpenFHE v1.4.2 source
- Building and installing OpenFHE C++ libraries
- Setting appropriate CGO flags for linking

No additional tools or manual configuration required.

## Run tests

```bash
make test
```

## Run examples

```
make run-examples
```

See examples and tests for usage

## Examples

### Boolean FHE
- [x] boolean-ap
- [x] boolean-lmkcdey
- [x] boolean-truth-tables
- [x] boolean

### PKE FHE
- [x] advanced-real-numbers-128
- [x] advanced-real-numbers
- [x] comparison-argmin (min/max with argmin/argmax via scheme switching)
- [x] function-evaluation (logistic, sin, cos, custom functions, batch optimization)
- [x] inner-product
- [x] interactive-bootstrapping
- [x] iterative-ckks-bootstrapping
- [x] linearwsum-evaluation
- [x] plaintext-operations
- [x] polynomial-evaluation
- [x] pre-buffer
- [x] pre-hra-secure
- [x] rotation
- [x] scheme-switching
- [x] simple-ckks-bootstrapping
- [x] simple-complex-numbers (complex number operations and bootstrapping)
- [x] simple-integers-bgvrns
- [x] simple-integers-serial-bgvrns
- [x] simple-integers-serial
- [x] simple-integers
- [x] simple-real-numbers-serial
- [x] simple-real-numbers
- [x] tckks-interactive-mp-bootstrapping-Chebyschev
- [x] tckks-interactive-mp-bootstrapping
- [x] threshold-fhe-5p
- [x] threshold-fhe

## Links

* https://openfhe.org/
* https://github.com/openfheorg/openfhe-development
