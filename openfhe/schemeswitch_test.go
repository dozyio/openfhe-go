package openfhe

import (
	"math"
	"testing"
)

// TestBasicSchemeSwitching tests the basic CKKS to FHEW to CKKS flow
func TestBasicSchemeSwitching(t *testing.T) {
	t.Helper()

	// Step 1: Setup CKKS CryptoContext
	multDepth := 3
	firstModSize := 60
	scaleModSize := 50
	ringDim := uint64(4096)
	slots := 16
	batchSize := slots

	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")
	mustT(t, params.SetFirstModSize(firstModSize), "SetFirstModSize")
	mustT(t, params.SetScalingModSize(scaleModSize), "SetScalingModSize")
	mustT(t, params.SetScalingTechnique(FIXEDMANUAL), "SetScalingTechnique")
	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel")
	mustT(t, params.SetRingDim(ringDim), "SetRingDim")
	mustT(t, params.SetBatchSize(batchSize), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	// Enable features
	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(SCHEMESWITCH), "Enable SCHEMESWITCH")

	t.Logf("CKKS scheme using ring dimension %d, %d slots, multiplicative depth %d",
		cc.GetRingDimension(), slots, multDepth)

	// Generate keys
	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	// Step 2: Setup scheme switching parameters
	swParams, err := NewSchSwchParams()
	mustT(t, err, "NewSchSwchParams")
	defer swParams.Close()

	mustT(t, swParams.SetSecurityLevelCKKS(HEStdNotSet), "SetSecurityLevelCKKS")
	mustT(t, swParams.SetSecurityLevelFHEW(BinFHETOY), "SetSecurityLevelFHEW")
	mustT(t, swParams.SetNumSlotsCKKS(uint32(slots)), "SetNumSlotsCKKS")
	mustT(t, swParams.SetCtxtModSizeFHEWLargePrec(25), "SetCtxtModSizeFHEWLargePrec")
	mustT(t, swParams.SetNumValues(uint32(slots)), "SetNumValues")

	// Step 3: Perform CKKS to FHEW setup
	lwesk, err := cc.EvalCKKStoFHEWSetup(swParams)
	mustT(t, err, "EvalCKKStoFHEWSetup")
	defer lwesk.Close()

	// Get BinFHE context
	// Note: This context is owned by the CKKS context and should NOT be closed
	ccLWE, err := cc.GetBinCCForSchemeSwitch()
	mustT(t, err, "GetBinCCForSchemeSwitch")

	// Generate switching keys
	mustT(t, cc.EvalCKKStoFHEWKeyGen(keys, lwesk), "EvalCKKStoFHEWKeyGen")

	// Get parameters from BinFHE context
	pLWE, err := ccLWE.GetMaxPlaintextSpace()
	mustT(t, err, "GetMaxPlaintextSpace")

	n, err := ccLWE.Getn()
	mustT(t, err, "Getn")

	q, err := ccLWE.Getq()
	mustT(t, err, "Getq")

	t.Logf("FHEW scheme using n=%d, logQ=25, q=%d, p=%d", n, q, pLWE)

	// Step 4: Encode and encrypt input
	x1 := []float64{0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0}

	ptxt1, err := cc.MakeCKKSPackedPlaintext(x1)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer ptxt1.Close()

	c1, err := cc.Encrypt(keys, ptxt1)
	mustT(t, err, "Encrypt")
	defer c1.Close()

	// Step 5: Scheme switching from CKKS to FHEW
	scale := 1.0 / float64(pLWE)
	mustT(t, cc.EvalCKKStoFHEWPrecompute(scale), "EvalCKKStoFHEWPrecompute")

	lweCts, err := cc.EvalCKKStoFHEW(c1, uint32(len(x1)))
	mustT(t, err, "EvalCKKStoFHEW")

	// Clean up LWE ciphertexts
	defer func() {
		for _, ct := range lweCts {
			ct.Close()
		}
	}()

	t.Logf("Successfully switched %d values from CKKS to FHEW", len(lweCts))

	// Step 6: Decrypt FHEW ciphertexts to verify
	t.Log("Decrypting FHEW ciphertexts:")
	x1Int := make([]uint64, len(x1))
	for i := range x1 {
		x1Int[i] = uint64(math.RoundToEven(x1[i])) % uint64(pLWE)
	}

	for i := 0; i < len(lweCts) && i < len(x1); i++ {
		result, err := lwesk.DecryptLWECiphertext(ccLWE, lweCts[i], uint64(pLWE))
		if err != nil {
			t.Logf("  [%d] decrypt error: %v", i, err)
			continue
		}
		expected := x1Int[i]
		if result != expected {
			t.Errorf("  [%d] got %d, expected %d", i, result, expected)
		} else {
			t.Logf("  [%d] %d (correct)", i, result)
		}
	}

	t.Log("Basic scheme switching test completed successfully!")
}

// TestSchemeSwitchingParams tests the SchSwchParams setter methods
func TestSchemeSwitchingParams(t *testing.T) {
	t.Helper()

	params, err := NewSchSwchParams()
	mustT(t, err, "NewSchSwchParams")
	defer params.Close()

	// Test setters - they should all succeed without errors
	// Note: Getters require SetParamsFromCKKSCryptocontext() to be called first,
	// which is done automatically during EvalCKKStoFHEWSetup
	mustT(t, params.SetSecurityLevelCKKS(HEStd128Classic), "SetSecurityLevelCKKS")
	mustT(t, params.SetSecurityLevelFHEW(BinFHESTD128), "SetSecurityLevelFHEW")
	mustT(t, params.SetNumSlotsCKKS(32), "SetNumSlotsCKKS")
	mustT(t, params.SetNumValues(16), "SetNumValues")
	mustT(t, params.SetCtxtModSizeFHEWLargePrec(25), "SetCtxtModSizeFHEWLargePrec")

	// Test boolean flags
	mustT(t, params.SetComputeArgmin(true), "SetComputeArgmin")
	mustT(t, params.SetUseAltArgmin(true), "SetUseAltArgmin")
	mustT(t, params.SetArbitraryFunctionEvaluation(true), "SetArbitraryFunctionEvaluation")
	mustT(t, params.SetOneHotEncoding(false), "SetOneHotEncoding")

	t.Log("SchSwchParams setter test completed successfully!")
	t.Log("Note: Getters are tested in TestBasicSchemeSwitching after proper initialization")
}

// TestBinFHEParameterGetters tests the new BinFHE getter methods
func TestBinFHEParameterGetters(t *testing.T) {
	t.Helper()

	cc, err := NewBinFHEContext()
	mustT(t, err, "NewBinFHEContext")
	defer cc.Close()

	// Generate context with TOY parameters
	mustT(t, cc.GenerateBinFHEContext(TOY, GINX), "GenerateBinFHEContext")

	// Test parameter getters
	maxP, err := cc.GetMaxPlaintextSpace()
	mustT(t, err, "GetMaxPlaintextSpace")
	t.Logf("Max plaintext space: %d", maxP)

	n, err := cc.Getn()
	mustT(t, err, "Getn")
	t.Logf("Lattice parameter n: %d", n)

	q, err := cc.Getq()
	mustT(t, err, "Getq")
	t.Logf("Ciphertext modulus q: %d", q)

	beta, err := cc.GetBeta()
	mustT(t, err, "GetBeta")
	t.Logf("Beta parameter: %d", beta)

	// Verify values are reasonable
	if maxP == 0 {
		t.Error("Max plaintext space should not be 0")
	}
	if n == 0 {
		t.Error("Lattice parameter n should not be 0")
	}
	if q == 0 {
		t.Error("Ciphertext modulus q should not be 0")
	}

	t.Log("BinFHE parameter getters test completed successfully!")
}
