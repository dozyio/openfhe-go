package openfhe

import "errors"

// Sentinel errors for common error conditions.
// These allow callers to use errors.Is() for error checking.
var (
	// Core object errors - PKE/FHE
	ErrContextClosed      = errors.New("CryptoContext is closed or invalid")
	ErrKeypairClosed      = errors.New("KeyPair is closed or invalid")
	ErrCiphertextNil      = errors.New("Ciphertext is closed or invalid")
	ErrInputCiphertextNil = errors.New("Input Ciphertext is closed or invalid")
	ErrPlaintextNil       = errors.New("Plaintext is closed or invalid")
	ErrPublicKeyNil       = errors.New("PublicKey is closed or invalid")
	ErrPrivateKeyNil      = errors.New("PrivateKey is closed or invalid")
	ErrSecretKeyNil       = errors.New("privateKey is nil or closed")
	ErrEvalKeyMapNil      = errors.New("EvalKeyMap is closed or invalid")
	ErrEvalKeyNil         = errors.New("EvalKey is closed or invalid")
	ErrFastRotationNil    = errors.New("FastRotationPrecompute is closed or invalid")
	ErrParamsCKKSNil      = errors.New("ParamsCKKS is closed or invalid")
	ErrParamsBGVNil       = errors.New("ParamsBGV is closed or invalid")
	ErrParamsBFVNil       = errors.New("ParamsBFV is closed or invalid")
	ErrSchSwchParamsNil   = errors.New("SchSwchParams is closed or invalid")

	// BinFHE object errors
	ErrBinFHEContextNil        = errors.New("BinFHEContext is closed or invalid")
	ErrBinFHESecretKeyNil      = errors.New("BinFHESecretKey is closed or invalid")
	ErrBinFHECiphertextNil     = errors.New("BinFHECiphertext is closed or invalid")
	ErrLWEPrivateKeyNil        = errors.New("LWEPrivateKey is closed or invalid")
	ErrLWECiphertextNil        = errors.New("LWE ciphertext is closed or invalid")
	ErrLWECiphertextArrayEmpty = errors.New("LWE ciphertext array is empty")

	// Input validation errors
	ErrEmptySlice               = errors.New("input slice is empty")
	ErrEmptyArray               = errors.New("ciphertext array is empty")
	ErrEmptyIndices             = errors.New("indices slice is empty")
	ErrEmptyData                = errors.New("cannot deserialize from empty data")
	ErrPrivateKeyArgNil         = errors.New("privateKey is nil")
	ErrPublicKeyArgNil          = errors.New("publicKey is nil")
	ErrCiphertextArgNil         = errors.New("ciphertext is nil")
	ErrEvalKeyArgNil            = errors.New("evalKey is nil")
	ErrInputBinFHECiphertextNil = errors.New("input BinFHECiphertext is closed or invalid")

	// Operation errors
	ErrNullHandle   = errors.New("operation returned OK but null handle")
	ErrNullString   = errors.New("operation returned null string")
	ErrNoPublicKey  = errors.New("KeyPair has no public key")
	ErrNoIndexFound = errors.New("no index found in one-hot vector (all values are 0)")
	ErrIndexCtNil   = errors.New("Index ciphertext is nil")

	// Serialization errors
	ErrSerializeFailed = errors.New("serialization failed")
)
