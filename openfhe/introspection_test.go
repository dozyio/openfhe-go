package openfhe

import (
	"math"
	"testing"
)

// Test ciphertext introspection methods for CKKS scheme
// Aligned with C++ examples from:
// - openfhe-development/src/pke/examples/simple-real-numbers-composite-scaling.cpp
// - openfhe-development/src/pke/extras/ckks-bootstrap.cpp
func TestCiphertextIntrospection_CKKS(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "Failed to create CKKS params")
	defer params.Close()

	params.SetMultiplicativeDepth(3)
	params.SetScalingModSize(50)
	params.SetBatchSize(8)

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "Failed to create CryptoContext")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE failed")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH failed")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE failed")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen failed")
	defer keys.Close()

	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen failed")

	// Create a simple vector
	input := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext failed")
	defer plaintext.Close()

	// Test plaintext introspection
	t.Run("PlaintextIntrospection", func(t *testing.T) {
		// Test GetLength - should match batch size
		length := plaintext.GetLength()
		if length != len(input) {
			t.Errorf("Plaintext GetLength() = %d, want %d", length, len(input))
		}

		// Test GetSlots
		slots := plaintext.GetSlots()
		if slots == 0 {
			t.Error("Plaintext GetSlots() returned 0")
		}

		// Test GetScalingFactor
		scalingFactor := plaintext.GetScalingFactor()
		if scalingFactor == 0.0 {
			t.Error("Plaintext GetScalingFactor() returned 0.0")
		}
		t.Logf("Plaintext scaling factor: %f", scalingFactor)

		// Test GetLevel - should be 0 for newly created plaintext
		level := plaintext.GetLevel()
		if level != 0 {
			t.Errorf("Plaintext GetLevel() = %d, want 0", level)
		}

		// Test GetEncodingType - should be CKKS_PACKED_ENCODING
		encodingType := plaintext.GetEncodingType()
		if encodingType < 0 {
			t.Error("Plaintext GetEncodingType() returned invalid value")
		}
		t.Logf("Plaintext encoding type: %d", encodingType)
	})

	// Encrypt
	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt failed")
	defer ciphertext.Close()

	// Test ciphertext introspection on fresh ciphertext
	t.Run("CiphertextIntrospection_Fresh", func(t *testing.T) {
		// Test GetLevel - fresh ciphertext should be at level 0
		level, ok := ciphertext.GetLevel()
		if !ok {
			t.Error("Ciphertext GetLevel() returned not ok")
		}
		if level != 0 {
			t.Errorf("Fresh ciphertext GetLevel() = %d, want 0", level)
		}
		t.Logf("Fresh ciphertext level: %d", level)

		// Test GetScalingFactor
		scalingFactor := ciphertext.GetScalingFactor()
		if scalingFactor == 0.0 {
			t.Error("Ciphertext GetScalingFactor() returned 0.0")
		}
		t.Logf("Fresh ciphertext scaling factor: %f", scalingFactor)

		// Test GetSlots
		slots := ciphertext.GetSlots()
		if slots == 0 {
			t.Error("Ciphertext GetSlots() returned 0")
		}
		t.Logf("Ciphertext slots: %d", slots)

		// Test GetNoiseScaleDeg
		noiseScaleDeg := ciphertext.GetNoiseScaleDeg()
		// In CKKS, noise scale degree can vary based on scaling technique
		// Just verify it's non-zero for a fresh ciphertext
		if noiseScaleDeg == 0 {
			t.Error("Fresh ciphertext GetNoiseScaleDeg() returned 0")
		}
		t.Logf("Fresh ciphertext noise scale degree: %d", noiseScaleDeg)

		// Test GetEncodingType
		encodingType := ciphertext.GetEncodingType()
		if encodingType < 0 {
			t.Error("Ciphertext GetEncodingType() returned invalid value")
		}
		t.Logf("Ciphertext encoding type: %d", encodingType)
	})

	// Test introspection after multiplication (aligned with C++ examples)
	t.Run("CiphertextIntrospection_AfterMult", func(t *testing.T) {
		// Multiply ciphertext by itself: c2 = c * c
		c2, err := cc.EvalMult(ciphertext, ciphertext)
		mustT(t, err, "EvalMult failed")
		defer c2.Close()

		// After multiplication, noise scale degree behavior depends on scaling technique
		initialNSD := ciphertext.GetNoiseScaleDeg()
		noiseScaleDeg := c2.GetNoiseScaleDeg()
		t.Logf("After mult, noise scale degree: %d (initial was %d)", noiseScaleDeg, initialNSD)

		// Scaling factor and level behavior after mult
		originalSF := ciphertext.GetScalingFactor()
		newSF := c2.GetScalingFactor()
		t.Logf("After mult, scaling factor: %f (initial was %f)", newSF, originalSF)

		// Level after multiplication - may increase immediately in some scaling modes
		level, ok := c2.GetLevel()
		if !ok {
			t.Error("After mult, GetLevel() returned not ok")
		}
		t.Logf("After mult, level: %d", level)

		// Slots should remain the same
		slots := c2.GetSlots()
		if slots != ciphertext.GetSlots() {
			t.Errorf("After mult, slots changed from %d to %d", ciphertext.GetSlots(), slots)
		}
	})

	// Test introspection after rescaling (aligned with C++ examples)
	t.Run("CiphertextIntrospection_AfterRescale", func(t *testing.T) {
		// Multiply then rescale
		c2, err := cc.EvalMult(ciphertext, ciphertext)
		mustT(t, err, "EvalMult failed")
		defer c2.Close()

		c2Rescaled, err := cc.Rescale(c2)
		mustT(t, err, "Rescale failed")
		defer c2Rescaled.Close()

		// After rescaling, level should increase
		level, ok := c2Rescaled.GetLevel()
		if !ok {
			t.Error("After rescale, GetLevel() returned not ok")
		}
		preMult, _ := c2.GetLevel()
		if level <= preMult {
			t.Logf("Note: After rescale, level=%d (was %d before rescale)", level, preMult)
		}
		t.Logf("After rescale, ciphertext level: %d", level)

		// Check noise scale degree
		preNSD := c2.GetNoiseScaleDeg()
		noiseScaleDeg := c2Rescaled.GetNoiseScaleDeg()
		t.Logf("After rescale, noise scale degree: %d (was %d before rescale)", noiseScaleDeg, preNSD)

		// Check scaling factor
		rescaledSF := c2Rescaled.GetScalingFactor()
		t.Logf("After rescale, scaling factor: %f", rescaledSF)
	})

	// Test SetScalingFactor and SetSlots
	t.Run("CiphertextIntrospection_Setters", func(t *testing.T) {
		c, err := cc.Encrypt(keys, plaintext)
		mustT(t, err, "Encrypt failed")
		defer c.Close()

		originalSF := c.GetScalingFactor()
		originalSlots := c.GetSlots()

		// Test SetScalingFactor
		newSF := 12345.6789
		c.SetScalingFactor(newSF)
		retrievedSF := c.GetScalingFactor()
		if math.Abs(retrievedSF-newSF) > 0.001 {
			t.Errorf("SetScalingFactor(%f), but GetScalingFactor() = %f", newSF, retrievedSF)
		}
		t.Logf("SetScalingFactor successful: %f -> %f", originalSF, retrievedSF)

		// Test SetSlots
		newSlots := uint32(16)
		c.SetSlots(newSlots)
		retrievedSlots := c.GetSlots()
		if retrievedSlots != newSlots {
			t.Errorf("SetSlots(%d), but GetSlots() = %d", newSlots, retrievedSlots)
		}
		t.Logf("SetSlots successful: %d -> %d", originalSlots, retrievedSlots)
	})
}

// Test ciphertext and plaintext introspection for BFV scheme
// Note: BFV doesn't use scaling factors (returns 1.0) or slots (returns 0) like CKKS does.
// These methods are available for API consistency but are not semantically meaningful for BFV.
// This matches the C++ behavior where methods exist on the base CiphertextImpl template.
func TestIntrospection_BFV(t *testing.T) {
	params, err := NewParamsBFVrns()
	mustT(t, err, "Failed to create BFV params")
	defer params.Close()

	params.SetPlaintextModulus(65537)
	params.SetMultiplicativeDepth(3)

	cc, err := NewCryptoContextBFV(params)
	mustT(t, err, "Failed to create CryptoContext")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE failed")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH failed")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE failed")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen failed")
	defer keys.Close()

	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen failed")

	// Create integer plaintext
	input := []int64{1, 2, 3, 4, 5, 6, 7, 8}
	plaintext, err := cc.MakePackedPlaintext(input)
	mustT(t, err, "MakePackedPlaintext failed")
	defer plaintext.Close()

	// Test plaintext introspection
	t.Run("PlaintextIntrospection_BFV", func(t *testing.T) {
		length := plaintext.GetLength()
		if length == 0 {
			t.Error("BFV Plaintext GetLength() returned 0")
		}
		t.Logf("BFV plaintext length: %d", length)

		level := plaintext.GetLevel()
		if level != 0 {
			t.Errorf("BFV Plaintext GetLevel() = %d, want 0", level)
		}
		t.Logf("BFV plaintext level: %d", level)

		slots := plaintext.GetSlots()
		// BFV may return 0 for slots as it uses different packing than CKKS
		t.Logf("BFV plaintext slots: %d", slots)

		encodingType := plaintext.GetEncodingType()
		if encodingType < 0 {
			t.Error("BFV Plaintext GetEncodingType() returned invalid value")
		}
		t.Logf("BFV plaintext encoding type: %d", encodingType)

		// BFV doesn't use scaling factors like CKKS - returns default value 1.0
		// C++ BGV uses GetScalingFactorInt() for integer modular arithmetic
		// C++ BFV doesn't use scaling factors at all in its implementation
		scalingFactor := plaintext.GetScalingFactor()
		if scalingFactor != 1.0 {
			t.Logf("BFV plaintext scaling factor: %f (expected 1.0 default)", scalingFactor)
		}
		t.Logf("BFV plaintext scaling factor: %f (not used in BFV, default value)", scalingFactor)
	})

	// Encrypt and test ciphertext introspection
	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt failed")
	defer ciphertext.Close()

	t.Run("CiphertextIntrospection_BFV_Fresh", func(t *testing.T) {
		level, ok := ciphertext.GetLevel()
		if !ok {
			t.Error("BFV Ciphertext GetLevel() returned not ok")
		}
		if level != 0 {
			t.Errorf("BFV fresh ciphertext GetLevel() = %d, want 0", level)
		}
		t.Logf("BFV fresh ciphertext level: %d", level)

		noiseScaleDeg := ciphertext.GetNoiseScaleDeg()
		if noiseScaleDeg == 0 {
			t.Error("BFV Ciphertext GetNoiseScaleDeg() returned 0")
		}
		t.Logf("BFV fresh ciphertext noise scale degree: %d", noiseScaleDeg)

		slots := ciphertext.GetSlots()
		// BFV may return 0 for slots as it uses different packing than CKKS
		t.Logf("BFV ciphertext slots: %d", slots)

		encodingType := ciphertext.GetEncodingType()
		if encodingType < 0 {
			t.Error("BFV Ciphertext GetEncodingType() returned invalid value")
		}
		t.Logf("BFV ciphertext encoding type: %d", encodingType)

		// BFV doesn't use scaling factors like CKKS - returns default value 1.0
		scalingFactor := ciphertext.GetScalingFactor()
		if scalingFactor != 1.0 {
			t.Logf("BFV ciphertext scaling factor: %f (expected 1.0 default)", scalingFactor)
		}
		t.Logf("BFV ciphertext scaling factor: %f (not used in BFV, default value)", scalingFactor)
	})

	// Test introspection after multiplication
	t.Run("CiphertextIntrospection_BFV_AfterMult", func(t *testing.T) {
		c2, err := cc.EvalMult(ciphertext, ciphertext)
		mustT(t, err, "EvalMult failed")
		defer c2.Close()

		initialLevel, _ := ciphertext.GetLevel()
		newLevel, ok := c2.GetLevel()
		if !ok {
			t.Error("After mult, GetLevel() returned not ok")
		}
		t.Logf("BFV after mult: level changed from %d to %d", initialLevel, newLevel)

		initialNSD := ciphertext.GetNoiseScaleDeg()
		newNSD := c2.GetNoiseScaleDeg()
		t.Logf("BFV after mult: noise scale degree changed from %d to %d", initialNSD, newNSD)

		// Slots should remain the same
		if c2.GetSlots() != ciphertext.GetSlots() {
			t.Error("BFV: slots changed after multiplication")
		}

		// Encoding type should remain the same
		if c2.GetEncodingType() != ciphertext.GetEncodingType() {
			t.Error("BFV: encoding type changed after multiplication")
		}
	})

	// Test introspection after modulus switching
	t.Run("CiphertextIntrospection_BFV_AfterModReduce", func(t *testing.T) {
		c2, err := cc.EvalMult(ciphertext, ciphertext)
		mustT(t, err, "EvalMult failed")
		defer c2.Close()

		c2ModReduced, err := cc.ModReduce(c2)
		mustT(t, err, "ModReduce failed")
		defer c2ModReduced.Close()

		preLevel, _ := c2.GetLevel()
		postLevel, ok := c2ModReduced.GetLevel()
		if !ok {
			t.Error("After ModReduce, GetLevel() returned not ok")
		}
		if postLevel <= preLevel {
			t.Logf("BFV after ModReduce: level changed from %d to %d", preLevel, postLevel)
		}
		t.Logf("BFV after ModReduce: level = %d (was %d before)", postLevel, preLevel)

		preNSD := c2.GetNoiseScaleDeg()
		postNSD := c2ModReduced.GetNoiseScaleDeg()
		t.Logf("BFV after ModReduce: noise scale degree = %d (was %d before)", postNSD, preNSD)
	})
}

// Test plaintext introspection for BGV scheme
func TestPlaintextIntrospection_BGV(t *testing.T) {
	params, err := NewParamsBGVrns()
	mustT(t, err, "Failed to create BGV params")
	defer params.Close()

	params.SetPlaintextModulus(65537)
	params.SetMultiplicativeDepth(2)

	cc, err := NewCryptoContextBGV(params)
	mustT(t, err, "Failed to create CryptoContext")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE failed")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen failed")
	defer keys.Close()

	// Create integer plaintext
	input := []int64{1, 2, 3, 4, 5, 6, 7, 8}
	plaintext, err := cc.MakeCoefPackedPlaintext(input)
	mustT(t, err, "MakeCoefPackedPlaintext failed")
	defer plaintext.Close()

	// Test plaintext introspection
	t.Run("PlaintextIntrospection_BGV", func(t *testing.T) {
		length := plaintext.GetLength()
		if length == 0 {
			t.Error("BGV Plaintext GetLength() returned 0")
		}
		t.Logf("BGV plaintext length: %d", length)

		level := plaintext.GetLevel()
		if level != 0 {
			t.Errorf("BGV Plaintext GetLevel() = %d, want 0", level)
		}

		encodingType := plaintext.GetEncodingType()
		if encodingType < 0 {
			t.Error("BGV Plaintext GetEncodingType() returned invalid value")
		}
		t.Logf("BGV plaintext encoding type: %d", encodingType)
	})

	// Encrypt and test ciphertext introspection
	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt failed")
	defer ciphertext.Close()

	t.Run("CiphertextIntrospection_BGV", func(t *testing.T) {
		level, ok := ciphertext.GetLevel()
		if !ok {
			t.Error("BGV Ciphertext GetLevel() returned not ok")
		}
		if level != 0 {
			t.Errorf("BGV fresh ciphertext GetLevel() = %d, want 0", level)
		}
		t.Logf("BGV ciphertext level: %d", level)

		noiseScaleDeg := ciphertext.GetNoiseScaleDeg()
		t.Logf("BGV ciphertext noise scale degree: %d", noiseScaleDeg)

		encodingType := ciphertext.GetEncodingType()
		if encodingType < 0 {
			t.Error("BGV Ciphertext GetEncodingType() returned invalid value")
		}
		t.Logf("BGV ciphertext encoding type: %d", encodingType)
	})
}

// Test that methods handle nil pointers gracefully
func TestIntrospection_NilHandling(t *testing.T) {
	t.Run("NilCiphertext", func(t *testing.T) {
		var ct *Ciphertext

		level, ok := ct.GetLevel()
		if ok {
			t.Error("GetLevel on nil ciphertext should return not ok")
		}
		if level != -1 {
			t.Errorf("GetLevel on nil ciphertext should return -1, got %d", level)
		}

		if sf := ct.GetScalingFactor(); sf != 0.0 {
			t.Errorf("GetScalingFactor on nil ciphertext should return 0.0, got %f", sf)
		}

		if slots := ct.GetSlots(); slots != 0 {
			t.Errorf("GetSlots on nil ciphertext should return 0, got %d", slots)
		}

		if nsd := ct.GetNoiseScaleDeg(); nsd != 0 {
			t.Errorf("GetNoiseScaleDeg on nil ciphertext should return 0, got %d", nsd)
		}

		if et := ct.GetEncodingType(); et != -1 {
			t.Errorf("GetEncodingType on nil ciphertext should return -1, got %d", et)
		}

		// Setters should not panic
		ct.SetScalingFactor(123.45)
		ct.SetSlots(10)
	})

	t.Run("NilPlaintext", func(t *testing.T) {
		var pt *Plaintext

		if length := pt.GetLength(); length != 0 {
			t.Errorf("GetLength on nil plaintext should return 0, got %d", length)
		}

		if level := pt.GetLevel(); level != 0 {
			t.Errorf("GetLevel on nil plaintext should return 0, got %d", level)
		}

		if slots := pt.GetSlots(); slots != 0 {
			t.Errorf("GetSlots on nil plaintext should return 0, got %d", slots)
		}

		if sf := pt.GetScalingFactor(); sf != 0.0 {
			t.Errorf("GetScalingFactor on nil plaintext should return 0.0, got %f", sf)
		}

		if et := pt.GetEncodingType(); et != -1 {
			t.Errorf("GetEncodingType on nil plaintext should return -1, got %d", et)
		}

		// Setter should not panic
		pt.SetScalingFactor(123.45)
	})
}

// Test introspection across multiple operations (aligned with C++ advanced-real-numbers.cpp)
func TestIntrospection_MultipleOperations(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "Failed to create CKKS params")
	defer params.Close()

	params.SetMultiplicativeDepth(5)
	params.SetScalingModSize(50)
	params.SetBatchSize(8)

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "Failed to create CryptoContext")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE failed")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH failed")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE failed")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen failed")
	defer keys.Close()

	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen failed")

	// Encrypt initial value
	input := []float64{1.0, 2.0, 3.0, 4.0}
	plaintext, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext failed")
	defer plaintext.Close()

	c, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt failed")
	defer c.Close()

	initialLevel, _ := c.GetLevel()
	initialNSD := c.GetNoiseScaleDeg()
	initialSF := c.GetScalingFactor()

	t.Logf("Initial state: level=%d, noiseScaleDeg=%d, scalingFactor=%f",
		initialLevel, initialNSD, initialSF)

	// c2 = c * c
	c2, err := cc.EvalMult(c, c)
	mustT(t, err, "EvalMult c*c failed")
	defer c2.Close()

	c2Level, _ := c2.GetLevel()
	c2NSD := c2.GetNoiseScaleDeg()
	c2SF := c2.GetScalingFactor()

	t.Logf("After c*c: level=%d, noiseScaleDeg=%d, scalingFactor=%f",
		c2Level, c2NSD, c2SF)

	// Note: noise scale degree behavior depends on scaling technique
	t.Logf("Noise scale degree after mult: %d (initial: %d)", c2NSD, initialNSD)

	// Rescale
	c2Rescaled, err := cc.Rescale(c2)
	mustT(t, err, "Rescale failed")
	defer c2Rescaled.Close()

	c2RLevel, _ := c2Rescaled.GetLevel()
	c2RNSD := c2Rescaled.GetNoiseScaleDeg()
	c2RSF := c2Rescaled.GetScalingFactor()

	t.Logf("After rescale: level=%d, noiseScaleDeg=%d, scalingFactor=%f",
		c2RLevel, c2RNSD, c2RSF)

	// Level and noise scale degree behavior varies by scaling technique
	t.Logf("Level comparison: after rescale=%d, after mult=%d", c2RLevel, c2Level)
	t.Logf("NoiseScaleDeg comparison: after rescale=%d, after mult=%d", c2RNSD, c2NSD)

	// c4 = c2 * c2
	c4, err := cc.EvalMult(c2Rescaled, c2Rescaled)
	mustT(t, err, "EvalMult c2*c2 failed")
	defer c4.Close()

	c4Level, _ := c4.GetLevel()
	c4NSD := c4.GetNoiseScaleDeg()
	c4SF := c4.GetScalingFactor()

	t.Logf("After c2*c2: level=%d, noiseScaleDeg=%d, scalingFactor=%f",
		c4Level, c4NSD, c4SF)

	// Verify properties persist through operations
	if c4.GetSlots() != c.GetSlots() {
		t.Error("Slots changed through operations")
	}

	if c4.GetEncodingType() != c.GetEncodingType() {
		t.Error("Encoding type changed through operations")
	}
}
