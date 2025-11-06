package openfhe

import (
	"testing"
)

// TestBFVParamsCreation tests basic BFV parameter creation
func TestBFVParamsCreation(t *testing.T) {
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	defer params.Close()

	if params.ptr == nil {
		t.Fatal("Expected non-nil params pointer")
	}
}

// TestBFVParamsSetters tests BFV parameter setter methods
func TestBFVParamsSetters(t *testing.T) {
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	defer params.Close()

	tests := []struct {
		name   string
		setter func() error
	}{
		{"SetPlaintextModulus", func() error { return params.SetPlaintextModulus(65537) }},
		{"SetMultiplicativeDepth", func() error { return params.SetMultiplicativeDepth(2) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.setter()
			if err != nil {
				t.Errorf("%s failed: %v", tt.name, err)
			}
		})
	}
}

// TestBFVParamsInvalidModulus tests error handling for invalid plaintext modulus
func TestBFVParamsInvalidModulus(t *testing.T) {
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	defer params.Close()

	// Test zero modulus - may or may not error depending on OpenFHE validation
	// This documents the behavior
	err = params.SetPlaintextModulus(0)
	t.Logf("SetPlaintextModulus(0) returned: %v", err)
}

// TestBFVParamsNegativeDepth tests error handling for negative depth
func TestBFVParamsNegativeDepth(t *testing.T) {
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	defer params.Close()

	// Test negative depth - may or may not error depending on OpenFHE validation
	err = params.SetMultiplicativeDepth(-1)
	t.Logf("SetMultiplicativeDepth(-1) returned: %v", err)
}

// TestBFVParamsClosedAccess tests operations on closed params
func TestBFVParamsClosedAccess(t *testing.T) {
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	params.Close()

	// After Close, operations should fail
	err = params.SetPlaintextModulus(65537)
	if err == nil {
		t.Error("Expected error when setting modulus on closed params")
	}

	err = params.SetMultiplicativeDepth(2)
	if err == nil {
		t.Error("Expected error when setting depth on closed params")
	}
}

// TestBFVParamsDoubleClose tests that double Close is safe
func TestBFVParamsDoubleClose(t *testing.T) {
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")

	params.Close()
	params.Close() // Should not panic
}

// TestBFVCryptoContextWithNilParams tests context creation with nil params
func TestBFVCryptoContextWithNilParams(t *testing.T) {
	_, err := NewCryptoContextBFV(nil)
	if err == nil {
		t.Error("Expected error when creating context with nil params")
	}
}

// TestBFVCryptoContextWithClosedParams tests context creation with closed params
func TestBFVCryptoContextWithClosedParams(t *testing.T) {
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	params.Close()

	_, err = NewCryptoContextBFV(params)
	if err == nil {
		t.Error("Expected error when creating context with closed params")
	}
}

// TestBFVMakePackedPlaintextEmpty tests empty vector handling
func TestBFVMakePackedPlaintextEmpty(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	empty := []int64{}
	_, err := cc.MakePackedPlaintext(empty)
	if err == nil {
		t.Error("Expected error when creating plaintext from empty vector")
	}
}

// TestBFVEncryptDecryptVariousSizes tests encryption/decryption with different vector sizes
func TestBFVEncryptDecryptVariousSizes(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	testCases := []struct {
		name string
		vec  []int64
	}{
		{"single", []int64{42}},
		{"small", []int64{1, 2, 3, 4}},
		{"medium", []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pt, err := cc.MakePackedPlaintext(tc.vec)
			mustT(t, err, "MakePackedPlaintext")
			defer pt.Close()

			ct, err := cc.Encrypt(keys, pt)
			mustT(t, err, "Encrypt")
			defer ct.Close()

			ptDec, err := cc.Decrypt(keys, ct)
			mustT(t, err, "Decrypt")
			defer ptDec.Close()

			result, err := ptDec.GetPackedValue()
			mustT(t, err, "GetPackedValue")

			if !slicesEqual(result[:len(tc.vec)], tc.vec) {
				t.Errorf("Mismatch for %s: expected %v, got %v", tc.name, tc.vec, result[:len(tc.vec)])
			}
		})
	}
}

// TestBFVArithmeticTableDriven tests BFV arithmetic operations with table-driven approach
func TestBFVArithmeticTableDriven(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	testCases := []struct {
		name     string
		v1       []int64
		v2       []int64
		expected []int64
		op       string
	}{
		{"add_simple", []int64{1, 2, 3, 4}, []int64{5, 6, 7, 8}, []int64{6, 8, 10, 12}, "add"},
		{"add_zero", []int64{1, 2, 3, 4}, []int64{0, 0, 0, 0}, []int64{1, 2, 3, 4}, "add"},
		{"mult_simple", []int64{2, 3, 4, 5}, []int64{3, 4, 5, 6}, []int64{6, 12, 20, 30}, "mult"},
		{"mult_by_one", []int64{7, 8, 9, 10}, []int64{1, 1, 1, 1}, []int64{7, 8, 9, 10}, "mult"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pt1, err := cc.MakePackedPlaintext(tc.v1)
			mustT(t, err, "MakePackedPlaintext v1")
			defer pt1.Close()

			pt2, err := cc.MakePackedPlaintext(tc.v2)
			mustT(t, err, "MakePackedPlaintext v2")
			defer pt2.Close()

			ct1, err := cc.Encrypt(keys, pt1)
			mustT(t, err, "Encrypt ct1")
			defer ct1.Close()

			ct2, err := cc.Encrypt(keys, pt2)
			mustT(t, err, "Encrypt ct2")
			defer ct2.Close()

			var ctResult *Ciphertext
			switch tc.op {
			case "add":
				ctResult, err = cc.EvalAdd(ct1, ct2)
				mustT(t, err, "EvalAdd")
			case "mult":
				ctResult, err = cc.EvalMult(ct1, ct2)
				mustT(t, err, "EvalMult")
			default:
				t.Fatalf("Unknown operation: %s", tc.op)
			}
			defer ctResult.Close()

			ptResult, err := cc.Decrypt(keys, ctResult)
			mustT(t, err, "Decrypt")
			defer ptResult.Close()

			result, err := ptResult.GetPackedValue()
			mustT(t, err, "GetPackedValue")

			vecLen := len(tc.expected)
			if !slicesEqual(result[:vecLen], tc.expected) {
				t.Errorf("%s %s failed: expected %v, got %v", tc.name, tc.op, tc.expected, result[:vecLen])
			}
		})
	}
}

// TestBFVNegativeNumbers tests BFV operations with negative numbers
func TestBFVNegativeNumbers(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vec := []int64{-1, -2, -3, -4, 5, 6, 7, 8}
	pt, err := cc.MakePackedPlaintext(vec)
	mustT(t, err, "MakePackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	ptDec, err := cc.Decrypt(keys, ct)
	mustT(t, err, "Decrypt")
	defer ptDec.Close()

	result, err := ptDec.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	vecLen := len(vec)
	// Note: negative numbers may be represented differently due to modular arithmetic
	t.Logf("Input: %v", vec)
	t.Logf("Output: %v", result[:vecLen])

	// The test documents the behavior - exact matching depends on plaintext modulus
}

// TestBFVLargeValues tests BFV with values near the plaintext modulus
func TestBFVLargeValues(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	// Values close to plaintext modulus (65537)
	// Note: 65535 and 65536 are represented as negative in OpenFHE's signed representation
	vec := []int64{32768, 16384, 8192, 4096}
	pt, err := cc.MakePackedPlaintext(vec)
	mustT(t, err, "MakePackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	ptDec, err := cc.Decrypt(keys, ct)
	mustT(t, err, "Decrypt")
	defer ptDec.Close()

	result, err := ptDec.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	vecLen := len(vec)
	if !slicesEqual(result[:vecLen], vec) {
		t.Errorf("Large values mismatch: expected %v, got %v", vec, result[:vecLen])
	}

	// Test that values at the modulus boundary are handled
	// Values like 65535 may be represented as -2 due to signed representation
	t.Log("Testing values near plaintext modulus boundary...")
	vecBoundary := []int64{65535, 65536}
	ptBoundary, err := cc.MakePackedPlaintext(vecBoundary)
	mustT(t, err, "MakePackedPlaintext boundary")
	defer ptBoundary.Close()

	ctBoundary, err := cc.Encrypt(keys, ptBoundary)
	mustT(t, err, "Encrypt boundary")
	defer ctBoundary.Close()

	ptBoundaryDec, err := cc.Decrypt(keys, ctBoundary)
	mustT(t, err, "Decrypt boundary")
	defer ptBoundaryDec.Close()

	resultBoundary, err := ptBoundaryDec.GetPackedValue()
	mustT(t, err, "GetPackedValue boundary")

	// Document the actual behavior (values may wrap around due to signed representation)
	t.Logf("Input: %v", vecBoundary)
	t.Logf("Output: %v (may differ due to signed modular representation)", resultBoundary[:len(vecBoundary)])
}

// TestBFVDepthExhaustion tests what happens when multiplicative depth is exhausted
func TestBFVDepthExhaustion(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vec := []int64{2, 2, 2, 2}
	pt, err := cc.MakePackedPlaintext(vec)
	mustT(t, err, "MakePackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	// Perform multiplications up to the depth limit (2)
	ct1, err := cc.EvalMult(ct, ct) // depth 1: 2^2 = 4
	mustT(t, err, "EvalMult 1")
	defer ct1.Close()

	ct2, err := cc.EvalMult(ct1, ct1) // depth 2: 4^2 = 16
	mustT(t, err, "EvalMult 2")
	defer ct2.Close()

	// Try one more multiplication beyond the depth - may or may not fail
	ct3, err := cc.EvalMult(ct2, ct2)
	if err != nil {
		t.Logf("Expected: multiplication beyond depth limit failed: %v", err)
		return
	}
	defer ct3.Close()

	// If it didn't fail, the result may be incorrect
	t.Log("Warning: multiplication beyond depth limit succeeded - result may be incorrect")
}

// TestBFVRotationEdgeCases tests rotation with edge case indices
func TestBFVRotationEdgeCases(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	// Generate rotation keys for edge cases
	rotIndices := []int32{0, 1, -1}
	mustT(t, cc.EvalRotateKeyGen(keys, rotIndices), "EvalRotateKeyGen")

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8}
	pt, err := cc.MakePackedPlaintext(vec)
	mustT(t, err, "MakePackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	// Rotate by 0 should return the same ciphertext
	ct0, err := cc.EvalRotate(ct, 0)
	mustT(t, err, "EvalRotate 0")
	defer ct0.Close()

	pt0, err := cc.Decrypt(keys, ct0)
	mustT(t, err, "Decrypt rotate 0")
	defer pt0.Close()

	result0, err := pt0.GetPackedValue()
	mustT(t, err, "GetPackedValue rotate 0")

	if !slicesEqual(result0[:len(vec)], vec) {
		t.Errorf("Rotate by 0 changed values: expected %v, got %v", vec, result0[:len(vec)])
	}
}
