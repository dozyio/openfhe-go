package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#cgo LDFLAGS: ${SRCDIR}/../openfhe-install/lib/libOPENFHEpke_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEcore_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEbinfhe_static.a -lc++ -lm
#include <stdint.h>
#include "bridge.h"
*/
import "C"

// --- Enums ---
const (
	PKE        = C.PKE_FEATURE
	KEYSWITCH  = C.KEYSWITCH_FEATURE
	LEVELEDSHE = C.LEVELEDSHE_FEATURE
)

// --- Structs ---
type (
	ParamsBFV  struct{ ptr C.ParamsBFVPtr }
	ParamsCKKS struct{ ptr C.ParamsCKKSPtr }
)

type (
	CryptoContext struct{ ptr C.CryptoContextPtr }
	KeyPair       struct{ ptr C.KeyPairPtr }
	Plaintext     struct{ ptr C.PlaintextPtr }
	Ciphertext    struct{ ptr C.CiphertextPtr }
)
