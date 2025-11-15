package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#cgo LDFLAGS: ${SRCDIR}/../openfhe-install/lib/libOPENFHEpke_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEcore_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEbinfhe_static.a
//CGO_SOURCES: pke_common_c.cpp bfv_c.cpp bgv_c.cpp ckks_c.cpp binfhe_c.cpp pre_c.cpp schemeswitch_c.cpp minmax_c.cpp

#include <stdint.h>
#include "binfhe_c.h"
#include "pke_common_c.h"
#include "bfv_c.h"
#include "bgv_c.h"
#include "ckks_c.h"
#include "pre_c.h"
#include "schemeswitch_c.h"
#include "minmax_c.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

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
	PKEErr           C.PKEErr
	BinFHEErr        C.BinFHEErr
)

const (
	PKE_OK  C.PKE_Err_Code = C.PKE_OK_CODE
	PKE_ERR C.PKE_Err_Code = C.PKE_ERR_CODE

	BINFHE_OK  C.BinFHEErrCode = C.BINFHE_OK_CODE
	BINFHE_ERR C.BinFHEErrCode = C.BINFHE_ERR_CODE
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

func checkPKEErrorMsg(cErr C.PKEErr) error {
	// Check the error code first
	if cErr.code == PKE_OK {
		if cErr.msg != nil {
			C.FreePKEErrMsg(cErr.msg) // Should be NULL on success, free anyway
		}
		return nil // Success
	}

	// An error occurred
	var goMsg string
	if cErr.msg != nil {
		// Use manual read first as GoString might still be problematic
		var goBytes []byte
		ptr := uintptr(unsafe.Pointer(cErr.msg))
		for {
			b := *(*byte)(unsafe.Pointer(ptr))
			if b == 0 {
				break
			}
			goBytes = append(goBytes, b)
			ptr++
		}
		goMsg = string(goBytes)

		// *** CRITICAL: Free the C string memory ***
		C.FreePKEErrMsg(cErr.msg)
	}

	// Fallback message if manual read failed somehow
	if goMsg == "" {
		goMsg = fmt.Sprintf("Unknown PKE C++ error (code %d, error message retrieval failed)", int(cErr.code))
	}

	return errors.New(goMsg)
}

func checkBinFHEErrorMsg(cErr C.BinFHEErr) error {
	// Check the error code first
	if cErr.code == BINFHE_OK {
		if cErr.msg != nil {
			C.FreeBinFHE_ErrMsg(cErr.msg) // Should be NULL on success, free anyway
		}
		return nil // Success
	}

	// An error occurred
	var goMsg string
	if cErr.msg != nil {
		// Use manual read first as GoString might still be problematic
		var goBytes []byte
		ptr := uintptr(unsafe.Pointer(cErr.msg))
		for {
			b := *(*byte)(unsafe.Pointer(ptr))
			if b == 0 {
				break
			}
			goBytes = append(goBytes, b)
			ptr++
		}
		goMsg = string(goBytes)

		// *** CRITICAL: Free the C string memory ***
		C.FreeBinFHE_ErrMsg(cErr.msg)
	}

	// Fallback message if manual read failed somehow
	if goMsg == "" {
		goMsg = fmt.Sprintf("Unknown PKE C++ error (code %d, error message retrieval failed)", int(cErr.code))
	}

	return errors.New(goMsg)
}
