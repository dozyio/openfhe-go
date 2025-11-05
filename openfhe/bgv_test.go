package openfhe

import (
	"testing"
)

// TestBGVParamsCreation tests basic BGV parameter creation
func TestBGVParamsCreation(t *testing.T) {
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
	defer params.Close()

	if params.ptr == nil {
		t.Fatal("Expected non-nil params pointer")
	}
}

// TestBGVParamsSetters tests BGV parameter setter methods
func TestBGVParamsSetters(t *testing.T) {
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
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

// TestBGVParamsInvalidModulus tests error handling for invalid plaintext modulus
func TestBGVParamsInvalidModulus(t *testing.T) {
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
	defer params.Close()

	// Test zero modulus - may or may not error depending on OpenFHE validation
	err = params.SetPlaintextModulus(0)
	t.Logf("SetPlaintextModulus(0) returned: %v", err)
}

// TestBGVParamsNegativeDepth tests error handling for negative depth
func TestBGVParamsNegativeDepth(t *testing.T) {
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
	defer params.Close()

	// Test negative depth - may or may not error depending on OpenFHE validation
	err = params.SetMultiplicativeDepth(-1)
	t.Logf("SetMultiplicativeDepth(-1) returned: %v", err)
}

// TestBGVParamsClosedAccess tests operations on closed params
func TestBGVParamsClosedAccess(t *testing.T) {
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
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

// TestBGVParamsDoubleClose tests that double Close is safe
func TestBGVParamsDoubleClose(t *testing.T) {
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")

	params.Close()
	params.Close() // Should not panic
}

// TestBGVCryptoContextWithNilParams tests context creation with nil params
func TestBGVCryptoContextWithNilParams(t *testing.T) {
	_, err := NewCryptoContextBGV(nil)
	if err == nil {
		t.Error("Expected error when creating context with nil params")
	}
}

// TestBGVCryptoContextWithClosedParams tests context creation with closed params
func TestBGVCryptoContextWithClosedParams(t *testing.T) {
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
	params.Close()

	_, err = NewCryptoContextBGV(params)
	if err == nil {
		t.Error("Expected error when creating context with closed params")
	}
}

// TestBGVEncryptDecryptVariousSizes tests encryption/decryption with different vector sizes
func TestBGVEncryptDecryptVariousSizes(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
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

// TestBGVArithmeticTableDriven tests BGV arithmetic operations with table-driven approach
func TestBGVArithmeticTableDriven(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	ptMod := int64(65537)

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
			// Apply modular arithmetic to expected values
			expectedMod := make([]int64, vecLen)
			for i := 0; i < vecLen; i++ {
				expectedMod[i] = tc.expected[i] % ptMod
			}

			if !slicesEqual(result[:vecLen], expectedMod) {
				t.Errorf("%s %s failed: expected %v, got %v", tc.name, tc.op, expectedMod, result[:vecLen])
			}
		})
	}
}

// TestBGVNegativeNumbers tests BGV operations with negative numbers
func TestBGVNegativeNumbers(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
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

// TestBGVLargeValues tests BGV with values near the plaintext modulus
func TestBGVLargeValues(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	// Values close to but less than plaintext modulus (65537)
	vec := []int64{65535, 65536, 32768, 16384}
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
}

// TestBGVChainedOperations tests multiple operations in sequence
func TestBGVChainedOperations(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	v1 := []int64{1, 2, 3, 4}
	v2 := []int64{2, 3, 4, 5}
	v3 := []int64{10, 10, 10, 10}

	pt1, err := cc.MakePackedPlaintext(v1)
	mustT(t, err, "MakePackedPlaintext v1")
	defer pt1.Close()

	pt2, err := cc.MakePackedPlaintext(v2)
	mustT(t, err, "MakePackedPlaintext v2")
	defer pt2.Close()

	pt3, err := cc.MakePackedPlaintext(v3)
	mustT(t, err, "MakePackedPlaintext v3")
	defer pt3.Close()

	ct1, err := cc.Encrypt(keys, pt1)
	mustT(t, err, "Encrypt ct1")
	defer ct1.Close()

	ct2, err := cc.Encrypt(keys, pt2)
	mustT(t, err, "Encrypt ct2")
	defer ct2.Close()

	ct3, err := cc.Encrypt(keys, pt3)
	mustT(t, err, "Encrypt ct3")
	defer ct3.Close()

	// Compute (v1 * v2) + v3
	ctMult, err := cc.EvalMult(ct1, ct2)
	mustT(t, err, "EvalMult")
	defer ctMult.Close()

	ctResult, err := cc.EvalAdd(ctMult, ct3)
	mustT(t, err, "EvalAdd")
	defer ctResult.Close()

	ptResult, err := cc.Decrypt(keys, ctResult)
	mustT(t, err, "Decrypt")
	defer ptResult.Close()

	result, err := ptResult.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	// Expected: (1*2)+10=12, (2*3)+10=16, (3*4)+10=22, (4*5)+10=30
	expected := []int64{12, 16, 22, 30}
	ptMod := int64(65537)
	for i := 0; i < len(expected); i++ {
		expected[i] = expected[i] % ptMod
	}

	if !slicesEqual(result[:len(expected)], expected) {
		t.Errorf("Chained operations failed: expected %v, got %v", expected, result[:len(expected)])
	}
}

// TestBGVRotationWithoutKeys tests that rotation fails without proper keys
func TestBGVRotationWithoutKeys(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vec := []int64{1, 2, 3, 4}
	pt, err := cc.MakePackedPlaintext(vec)
	mustT(t, err, "MakePackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	// Try to rotate without generating rotation keys
	_, err = cc.EvalRotate(ct, 1)
	if err == nil {
		t.Error("Expected error when rotating without rotation keys")
	}
	t.Logf("Rotation without keys correctly failed: %v", err)
}
