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

### Prerequisites

For faster compilation (recommended), install ccache:
```bash
brew install ccache  # macOS
# or
apt install ccache   # Linux
```

### Build the project

```bash
make build
```

**Build times:**
- First build: ~15 seconds (with ccache, cold cache)
- Rebuild: ~8 seconds (with ccache, warm cache)
- No-op build: ~0.1 seconds (fully cached)
- Without ccache: ~100 seconds

**Important:** ccache is automatically used when building through `make`. If you run `go build` or `go test` directly, you need to either:

1. **Use make targets** (recommended):
   ```bash
   make build
   make test
   ```

2. **Set environment variables** in your shell/IDE:
   ```bash
   export CC="ccache clang"
   export CXX="ccache clang++"
   go build ./openfhe
   go test ./openfhe
   ```

3. **Configure your editor/IDE** (for gopls and test runners):
   - **VS Code** (`settings.json`):
     ```json
     {
       "go.toolsEnvVars": {
         "CC": "ccache clang",
         "CXX": "ccache clang++"
       }
     }
     ```
   - **Neovim/Vim**:
     ```lua
     vim.env.CC = "ccache clang"
     vim.env.CXX = "ccache clang++"
     ```

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
- [ ] iterative-ckks-bootstrapping
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
- [ ] simple-integers-serial-bgvrns
- [x] simple-integers-serial
- [x] simple-integers
- [x] simple-real-numbers-serial
- [x] simple-real-numbers
- [ ] tckks-interactive-mp-bootstrapping-Chebyschev
- [ ] tckks-interactive-mp-bootstrapping
- [x] threshold-fhe-5p
- [x] threshold-fhe

## Links

* https://openfhe.org/
* https://github.com/openfheorg/openfhe-development
