package openfhe

import (
	"testing"
)

// TestGetPackedValueBulk verifies bulk getter works correctly
func TestGetPackedValueBulk(t *testing.T) {
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	defer params.Close()

	mustT(t, params.SetPlaintextModulus(65537), "SetPlaintextModulus")
	mustT(t, params.SetMultiplicativeDepth(1), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextBFV(params)
	mustT(t, err, "NewCryptoContextBFV")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	input := []int64{1, 2, 3, 4, 5}
	pt, err := cc.MakePackedPlaintext(input)
	mustT(t, err, "MakePackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	result, err := cc.Decrypt(keys, ct)
	mustT(t, err, "Decrypt")
	defer result.Close()

	output, err := result.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	if len(output) < len(input) {
		t.Fatalf("Output length %d < input length %d", len(output), len(input))
	}

	for i := range input {
		if output[i] != input[i] {
			t.Errorf("output[%d] = %d, want %d", i, output[i], input[i])
		}
	}
}

// TestGetRealPackedValueBulk verifies bulk getter works for CKKS real values
func TestGetRealPackedValueBulk(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(1), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	input := []float64{1.1, 2.2, 3.3, 4.4, 5.5}
	pt, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	result, err := cc.Decrypt(keys, ct)
	mustT(t, err, "Decrypt")
	defer result.Close()

	output, err := result.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	if len(output) < len(input) {
		t.Fatalf("Output length %d < input length %d", len(output), len(input))
	}

	const epsilon = 0.01
	for i := range input {
		diff := output[i] - input[i]
		if diff < 0 {
			diff = -diff
		}
		if diff > epsilon {
			t.Errorf("output[%d] = %f, want %f (diff %f > %f)", i, output[i], input[i], diff, epsilon)
		}
	}
}

// TestGetComplexPackedValueBulk verifies bulk getter works for CKKS complex values
func TestGetComplexPackedValueBulk(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(1), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetBatchSize(8), "SetBatchSize")
	mustT(t, params.SetCKKSDataType(CKKS_DATA_TYPE_COMPLEX), "SetCKKSDataType")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	input := []complex128{1 + 1i, 2 + 2i, 3 + 3i}
	pt, err := cc.MakeCKKSComplexPackedPlaintext(input)
	mustT(t, err, "MakeCKKSComplexPackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	result, err := cc.Decrypt(keys, ct)
	mustT(t, err, "Decrypt")
	defer result.Close()

	output, err := result.GetComplexPackedValue()
	mustT(t, err, "GetComplexPackedValue")

	if len(output) < len(input) {
		t.Fatalf("Output length %d < input length %d", len(output), len(input))
	}

	const epsilon = 0.01
	for i := range input {
		realDiff := real(output[i]) - real(input[i])
		imagDiff := imag(output[i]) - imag(input[i])
		if realDiff < 0 {
			realDiff = -realDiff
		}
		if imagDiff < 0 {
			imagDiff = -imagDiff
		}
		if realDiff > epsilon || imagDiff > epsilon {
			t.Errorf("output[%d] = %v, want %v (realDiff=%.10f, imagDiff=%.10f)",
				i, output[i], input[i], realDiff, imagDiff)
		}
	}
}
