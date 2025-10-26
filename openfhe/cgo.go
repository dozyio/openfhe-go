package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#cgo LDFLAGS: ${SRCDIR}/../openfhe-install/lib/libOPENFHEpke_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEcore_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEbinfhe_static.a -lc++ -lm
#include <stdint.h>
#include "bridge.h"
*/
import "C"

// --- Structs ---
type (
	ParamsBFV  struct{ ptr C.ParamsBFVPtr }
	ParamsCKKS struct{ ptr C.ParamsCKKSPtr }
)

type (
	CryptoContext    struct{ ptr C.CryptoContextPtr }
	KeyPair          struct{ ptr C.KeyPairPtr }
	Plaintext        struct{ ptr C.PlaintextPtr }
	Ciphertext       struct{ ptr C.CiphertextPtr }
	DistributionType C.DistributionType
	SecurityLevel    C.OFHESecurityLevel
	SecretKeyDist    C.OFHESecretKeyDist
)

const (
	HEStdUniform DistributionType = C.HEStd_uniform
	HEStdError   DistributionType = C.HEStd_error
	HEStdTernary DistributionType = C.HEStd_ternary
)

const (
	HEStd128Classic SecurityLevel = C.HEStd_128_classic
	HEStd192Classic SecurityLevel = C.HEStd_192_classic
	HEStd256Classic SecurityLevel = C.HEStd_256_classic
	HEStd128Quantum SecurityLevel = C.HEStd_128_quantum
	HEStd192Quantum SecurityLevel = C.HEStd_192_quantum
	HEStd256Quantum SecurityLevel = C.HEStd_256_quantum
	HEStdNotSet     SecurityLevel = C.HEStd_NotSet
)

const (
	SecretKeyGaussian           SecretKeyDist = C.GAUSSIAN
	SecretKeyUniformTernary     SecretKeyDist = C.UNIFORM_TERNARY
	SecretKeySparseTernary      SecretKeyDist = C.SPARSE_TERNARY
	SecretKeySparseEncapsulated SecretKeyDist = C.SPARSE_ENCAPSULATED
)
