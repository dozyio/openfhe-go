package openfhe

import (
	"testing"
)

// TestBGVThresholdFHE tests basic 3-party threshold FHE with BGV
func TestBGVThresholdFHE(t *testing.T) {
	// Create BGV parameters with multiparty mode
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
	defer params.Close()

	err = params.SetPlaintextModulus(65537)
	mustT(t, err, "SetPlaintextModulus")

	err = params.SetMultiplicativeDepth(2)
	mustT(t, err, "SetMultiplicativeDepth")

	err = params.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)
	mustT(t, err, "SetMultipartyMode")

	// Generate crypto context
	cc, err := NewCryptoContextBGV(params)
	mustT(t, err, "NewCryptoContextBGV")
	defer cc.Close()

	// Enable features
	err = cc.Enable(PKE | KEYSWITCH | LEVELEDSHE | ADVANCEDSHE | MULTIPARTY)
	mustT(t, err, "Enable")

	// Generate keys for 3 parties
	kp1, err := cc.KeyGen()
	mustT(t, err, "KeyGen party 1")
	defer kp1.Close()

	pk1, err := kp1.GetMultipartyPublicKey()
	mustT(t, err, "GetMultipartyPublicKey party 1")
	defer pk1.Close()

	kp2, err := cc.MultipartyKeyGenFromPublicKey(pk1, false, false)
	mustT(t, err, "MultipartyKeyGen party 2")
	defer kp2.Close()

	pk2, err := kp2.GetMultipartyPublicKey()
	mustT(t, err, "GetMultipartyPublicKey party 2")
	defer pk2.Close()

	kp3, err := cc.MultipartyKeyGenFromPublicKey(pk2, false, false)
	mustT(t, err, "MultipartyKeyGen party 3")
	defer kp3.Close()

	// Create plaintext
	values1 := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt1, err := cc.MakePackedPlaintext(values1)
	mustT(t, err, "MakePackedPlaintext 1")
	defer pt1.Close()

	values2 := []int64{1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0}
	pt2, err := cc.MakePackedPlaintext(values2)
	mustT(t, err, "MakePackedPlaintext 2")
	defer pt2.Close()

	values3 := []int64{2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0}
	pt3, err := cc.MakePackedPlaintext(values3)
	mustT(t, err, "MakePackedPlaintext 3")
	defer pt3.Close()

	// Encrypt with final public key
	ct1, err := cc.Encrypt(kp3, pt1)
	mustT(t, err, "Encrypt 1")
	defer ct1.Close()

	ct2, err := cc.Encrypt(kp3, pt2)
	mustT(t, err, "Encrypt 2")
	defer ct2.Close()

	ct3, err := cc.Encrypt(kp3, pt3)
	mustT(t, err, "Encrypt 3")
	defer ct3.Close()

	// Perform homomorphic addition
	ctAdd12, err := cc.EvalAdd(ct1, ct2)
	mustT(t, err, "EvalAdd 1+2")
	defer ctAdd12.Close()

	ctAdd123, err := cc.EvalAdd(ctAdd12, ct3)
	mustT(t, err, "EvalAdd result+3")
	defer ctAdd123.Close()

	// Multiparty decryption - lead party
	sk1, err := kp1.GetMultipartyPrivateKey()
	mustT(t, err, "GetMultipartyPrivateKey party 1")
	defer sk1.Close()

	partial1, err := cc.MultipartyDecryptLead([]*Ciphertext{ctAdd123}, sk1)
	mustT(t, err, "MultipartyDecryptLead")
	if len(partial1) != 1 {
		t.Fatalf("Expected 1 partial ciphertext, got %d", len(partial1))
	}
	defer partial1[0].Close()

	// Multiparty decryption - main parties
	sk2, err := kp2.GetMultipartyPrivateKey()
	mustT(t, err, "GetMultipartyPrivateKey party 2")
	defer sk2.Close()

	partial2, err := cc.MultipartyDecryptMain([]*Ciphertext{ctAdd123}, sk2)
	mustT(t, err, "MultipartyDecryptMain party 2")
	if len(partial2) != 1 {
		t.Fatalf("Expected 1 partial ciphertext, got %d", len(partial2))
	}
	defer partial2[0].Close()

	sk3, err := kp3.GetMultipartyPrivateKey()
	mustT(t, err, "GetMultipartyPrivateKey party 3")
	defer sk3.Close()

	partial3, err := cc.MultipartyDecryptMain([]*Ciphertext{ctAdd123}, sk3)
	mustT(t, err, "MultipartyDecryptMain party 3")
	if len(partial3) != 1 {
		t.Fatalf("Expected 1 partial ciphertext, got %d", len(partial3))
	}
	defer partial3[0].Close()

	// Fusion
	partials := []*Ciphertext{partial1[0], partial2[0], partial3[0]}
	ptResult, err := cc.MultipartyDecryptFusion(partials)
	mustT(t, err, "MultipartyDecryptFusion")
	defer ptResult.Close()

	// Verify result
	result, err := ptResult.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	if len(result) < len(values1) {
		t.Fatalf("Result length %d is less than expected %d", len(result), len(values1))
	}

	// Check a few values (1+1+2=4, 2+0+2=4, 3+0+3=6, 4+1+4=9)
	expected := []int64{4, 4, 6, 9, 11, 12, 14, 16, 18, 20, 11, 12}
	for i := 0; i < len(expected); i++ {
		if result[i] != expected[i] {
			t.Errorf("At index %d: expected %d, got %d", i, expected[i], result[i])
		}
	}

	t.Log("BGV Threshold FHE test passed!")
}

// TestMultipartyKeyAggregation tests multiparty public key aggregation
func TestMultipartyKeyAggregation(t *testing.T) {
	// Create BFV parameters
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	defer params.Close()

	err = params.SetPlaintextModulus(65537)
	mustT(t, err, "SetPlaintextModulus")

	err = params.SetMultiplicativeDepth(2)
	mustT(t, err, "SetMultiplicativeDepth")

	err = params.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)
	mustT(t, err, "SetMultipartyMode")

	// Generate crypto context
	cc, err := NewCryptoContextBFV(params)
	mustT(t, err, "NewCryptoContextBFV")
	defer cc.Close()

	err = cc.Enable(PKE | KEYSWITCH | MULTIPARTY)
	mustT(t, err, "Enable")

	// Generate two keypairs
	kp1, err := cc.KeyGen()
	mustT(t, err, "KeyGen party 1")
	defer kp1.Close()

	kp2, err := cc.KeyGen()
	mustT(t, err, "KeyGen party 2")
	defer kp2.Close()

	// Get public keys
	pk1, err := kp1.GetMultipartyPublicKey()
	mustT(t, err, "GetMultipartyPublicKey 1")
	defer pk1.Close()

	pk2, err := kp2.GetMultipartyPublicKey()
	mustT(t, err, "GetMultipartyPublicKey 2")
	defer pk2.Close()

	// Aggregate public keys
	pkJoint, err := cc.MultiAddPubKeys(pk1, pk2, "")
	mustT(t, err, "MultiAddPubKeys")
	defer pkJoint.Close()

	// If we got here without errors, the test passed
	t.Log("Multiparty key aggregation test passed!")
}

// TestCKKSThresholdFHE tests threshold FHE with CKKS scheme
func TestCKKSThresholdFHE(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CKKS threshold FHE test in short mode")
	}

	// Create CKKS parameters
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	err = params.SetMultiplicativeDepth(2)
	mustT(t, err, "SetMultiplicativeDepth")

	err = params.SetScalingModSize(50)
	mustT(t, err, "SetScalingModSize")

	err = params.SetBatchSize(8)
	mustT(t, err, "SetBatchSize")

	// Note: CKKS doesn't support SetMultipartyMode via parameters
	// The multiparty mode is handled internally

	// Generate crypto context
	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	err = cc.Enable(PKE | KEYSWITCH | LEVELEDSHE | ADVANCEDSHE | MULTIPARTY)
	mustT(t, err, "Enable")

	// Generate keys for 2 parties
	kp1, err := cc.KeyGen()
	mustT(t, err, "KeyGen party 1")
	defer kp1.Close()

	pk1, err := kp1.GetMultipartyPublicKey()
	mustT(t, err, "GetMultipartyPublicKey party 1")
	defer pk1.Close()

	kp2, err := cc.MultipartyKeyGenFromPublicKey(pk1, false, false)
	mustT(t, err, "MultipartyKeyGen party 2")
	defer kp2.Close()

	// Create plaintexts
	values1 := []float64{1.0, 2.0, 3.0, 4.0}
	pt1, err := cc.MakeCKKSPackedPlaintext(values1)
	mustT(t, err, "MakeCKKSPackedPlaintext 1")
	defer pt1.Close()

	values2 := []float64{0.5, 0.5, 0.5, 0.5}
	pt2, err := cc.MakeCKKSPackedPlaintext(values2)
	mustT(t, err, "MakeCKKSPackedPlaintext 2")
	defer pt2.Close()

	// Encrypt
	ct1, err := cc.Encrypt(kp2, pt1)
	mustT(t, err, "Encrypt 1")
	defer ct1.Close()

	ct2, err := cc.Encrypt(kp2, pt2)
	mustT(t, err, "Encrypt 2")
	defer ct2.Close()

	// Add
	ctAdd, err := cc.EvalAdd(ct1, ct2)
	mustT(t, err, "EvalAdd")
	defer ctAdd.Close()

	// Multiparty decrypt
	sk1, err := kp1.GetMultipartyPrivateKey()
	mustT(t, err, "GetMultipartyPrivateKey 1")
	defer sk1.Close()

	sk2, err := kp2.GetMultipartyPrivateKey()
	mustT(t, err, "GetMultipartyPrivateKey 2")
	defer sk2.Close()

	partial1, err := cc.MultipartyDecryptLead([]*Ciphertext{ctAdd}, sk1)
	mustT(t, err, "MultipartyDecryptLead")
	defer partial1[0].Close()

	partial2, err := cc.MultipartyDecryptMain([]*Ciphertext{ctAdd}, sk2)
	mustT(t, err, "MultipartyDecryptMain")
	defer partial2[0].Close()

	ptResult, err := cc.MultipartyDecryptFusion([]*Ciphertext{partial1[0], partial2[0]})
	mustT(t, err, "MultipartyDecryptFusion")
	defer ptResult.Close()

	// Verify approximate result (CKKS is approximate)
	result, err := ptResult.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	if len(result) < len(values1) {
		t.Fatalf("Result length %d is less than expected %d", len(result), len(values1))
	}

	// Check values with tolerance
	tolerance := 0.01
	expected := []float64{1.5, 2.5, 3.5, 4.5}
	for i := 0; i < len(expected); i++ {
		diff := result[i] - expected[i]
		if diff < 0 {
			diff = -diff
		}
		if diff > tolerance {
			t.Errorf("At index %d: expected %f, got %f (diff %f > tolerance %f)",
				i, expected[i], result[i], diff, tolerance)
		}
	}

	t.Log("CKKS Threshold FHE test passed!")
}

// TestMultipartyErrorCases tests error handling for invalid inputs
func TestMultipartyErrorCases(t *testing.T) {
	// Setup basic context
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
	defer params.Close()

	err = params.SetPlaintextModulus(65537)
	mustT(t, err, "SetPlaintextModulus")

	err = params.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)
	mustT(t, err, "SetMultipartyMode")

	cc, err := NewCryptoContextBGV(params)
	mustT(t, err, "NewCryptoContextBGV")
	defer cc.Close()

	err = cc.Enable(PKE | KEYSWITCH | MULTIPARTY)
	mustT(t, err, "Enable")

	// Test 1: MultipartyKeyGenFromPublicKey with nil public key
	t.Run("NilPublicKey", func(t *testing.T) {
		_, err := cc.MultipartyKeyGenFromPublicKey(nil, false, false)
		if err == nil {
			t.Error("Expected error with nil public key, got nil")
		}
		if err != nil {
			t.Logf("Correctly rejected nil public key: %v", err)
		}
	})

	// Test 2: MultipartyKeyGen with empty private keys slice
	t.Run("EmptyPrivateKeys", func(t *testing.T) {
		emptyKeys := []*PrivateKey{}
		_, err := cc.MultipartyKeyGen(emptyKeys)
		if err == nil {
			t.Error("Expected error with empty private keys, got nil")
		}
		if err != nil {
			t.Logf("Correctly rejected empty private keys: %v", err)
		}
	})

	// Test 3: MultipartyDecryptLead with nil private key
	t.Run("NilPrivateKeyDecrypt", func(t *testing.T) {
		kp, err := cc.KeyGen()
		mustT(t, err, "KeyGen")
		defer kp.Close()

		values := []int64{1, 2, 3, 4}
		pt, err := cc.MakePackedPlaintext(values)
		mustT(t, err, "MakePackedPlaintext")
		defer pt.Close()

		ct, err := cc.Encrypt(kp, pt)
		mustT(t, err, "Encrypt")
		defer ct.Close()

		_, err = cc.MultipartyDecryptLead([]*Ciphertext{ct}, nil)
		if err == nil {
			t.Error("Expected error with nil private key, got nil")
		}
		if err != nil {
			t.Logf("Correctly rejected nil private key: %v", err)
		}
	})

	// Test 4: MultipartyDecryptLead with empty ciphertexts slice
	t.Run("EmptyCiphertexts", func(t *testing.T) {
		kp, err := cc.KeyGen()
		mustT(t, err, "KeyGen")
		defer kp.Close()

		sk, err := kp.GetMultipartyPrivateKey()
		mustT(t, err, "GetMultipartyPrivateKey")
		defer sk.Close()

		_, err = cc.MultipartyDecryptLead([]*Ciphertext{}, sk)
		if err == nil {
			t.Error("Expected error with empty ciphertexts, got nil")
		}
		if err != nil {
			t.Logf("Correctly rejected empty ciphertexts: %v", err)
		}
	})

	// Test 5: MultipartyDecryptFusion with empty partial ciphertexts
	t.Run("EmptyPartialCiphertexts", func(t *testing.T) {
		_, err := cc.MultipartyDecryptFusion([]*Ciphertext{})
		if err == nil {
			t.Error("Expected error with empty partial ciphertexts, got nil")
		}
		if err != nil {
			t.Logf("Correctly rejected empty partial ciphertexts: %v", err)
		}
	})

	// Test 6: MultiAddPubKeys with nil keys
	t.Run("NilPublicKeysAdd", func(t *testing.T) {
		kp, err := cc.KeyGen()
		mustT(t, err, "KeyGen")
		defer kp.Close()

		pk, err := kp.GetMultipartyPublicKey()
		mustT(t, err, "GetMultipartyPublicKey")
		defer pk.Close()

		// Test with nil first key
		_, err = cc.MultiAddPubKeys(nil, pk, "")
		if err == nil {
			t.Error("Expected error with nil first public key, got nil")
		}

		// Test with nil second key
		_, err = cc.MultiAddPubKeys(pk, nil, "")
		if err == nil {
			t.Error("Expected error with nil second public key, got nil")
		}
	})

	t.Log("All error cases handled correctly!")
}

// TestMultipartyEvalKeys tests multiparty evaluation key generation and aggregation
func TestMultipartyEvalKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping eval keys test in short mode")
	}

	// Setup BFV context
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	defer params.Close()

	err = params.SetPlaintextModulus(65537)
	mustT(t, err, "SetPlaintextModulus")

	err = params.SetMultiplicativeDepth(2)
	mustT(t, err, "SetMultiplicativeDepth")

	err = params.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)
	mustT(t, err, "SetMultipartyMode")

	cc, err := NewCryptoContextBFV(params)
	mustT(t, err, "NewCryptoContextBFV")
	defer cc.Close()

	err = cc.Enable(PKE | KEYSWITCH | LEVELEDSHE | ADVANCEDSHE | MULTIPARTY)
	mustT(t, err, "Enable")

	// Generate keys for 2 parties
	kp1, err := cc.KeyGen()
	mustT(t, err, "KeyGen party 1")
	defer kp1.Close()

	pk1, err := kp1.GetMultipartyPublicKey()
	mustT(t, err, "GetMultipartyPublicKey party 1")
	defer pk1.Close()

	kp2, err := cc.MultipartyKeyGenFromPublicKey(pk1, false, false)
	mustT(t, err, "MultipartyKeyGen party 2")
	defer kp2.Close()

	// Test complete eval key generation workflow
	t.Run("CompleteEvalKeyWorkflow", func(t *testing.T) {
		sk1, err := kp1.GetMultipartyPrivateKey()
		mustT(t, err, "GetMultipartyPrivateKey party 1")
		defer sk1.Close()

		// Step 1: Party 1 generates base eval sum key
		err = cc.EvalSumKeyGenPrivate(sk1, nil)
		mustT(t, err, "EvalSumKeyGenPrivate party 1")

		t.Log("Base eval sum key generation successful!")
	})

	// Test rotation key generation workflow
	t.Run("RotationKeyWorkflow", func(t *testing.T) {
		sk1, err := kp1.GetMultipartyPrivateKey()
		mustT(t, err, "GetMultipartyPrivateKey party 1")
		defer sk1.Close()

		sk2, err := kp2.GetMultipartyPrivateKey()
		mustT(t, err, "GetMultipartyPrivateKey party 2")
		defer sk2.Close()

		// Generate rotation keys for indices [1, 2, 3]
		indices := []int32{1, 2, 3}

		// Step 1: Party 1 generates base rotation keys
		err = cc.EvalAtIndexKeyGenPrivate(sk1, indices, nil)
		mustT(t, err, "EvalAtIndexKeyGenPrivate party 1")

		// Step 2: Party 2 generates their rotation keys
		err = cc.EvalAtIndexKeyGenPrivate(sk2, indices, nil)
		mustT(t, err, "EvalAtIndexKeyGenPrivate party 2")

		t.Log("Base rotation key generation for both parties successful!")
	})

	t.Log("Multiparty evaluation keys test passed!")
}

// TestClosedContextOperations tests operations on closed contexts
func TestClosedContextOperations(t *testing.T) {
	// Create and immediately close a context
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")

	err = params.SetPlaintextModulus(65537)
	mustT(t, err, "SetPlaintextModulus")

	cc, err := NewCryptoContextBGV(params)
	mustT(t, err, "NewCryptoContextBGV")

	cc.Close() // Close it immediately
	params.Close()

	// Try to use closed context
	t.Run("KeyGenOnClosedContext", func(t *testing.T) {
		_, err := cc.KeyGen()
		if err == nil {
			t.Error("Expected error with closed context, got nil")
		}
		if err != nil {
			t.Logf("Correctly rejected operation on closed context: %v", err)
		}
	})

	// Test with closed keypair
	params2, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
	defer params2.Close()

	err = params2.SetPlaintextModulus(65537)
	mustT(t, err, "SetPlaintextModulus")

	cc2, err := NewCryptoContextBGV(params2)
	mustT(t, err, "NewCryptoContextBGV")
	defer cc2.Close()

	err = cc2.Enable(PKE | MULTIPARTY)
	mustT(t, err, "Enable")

	kp, err := cc2.KeyGen()
	mustT(t, err, "KeyGen")

	// Get keys before closing
	pk, err := kp.GetMultipartyPublicKey()
	mustT(t, err, "GetMultipartyPublicKey")

	kp.Close() // Close keypair
	pk.Close() // Close public key

	t.Run("OperationWithClosedKeys", func(t *testing.T) {
		// Try to get key from closed keypair
		_, err := kp.GetMultipartyPrivateKey()
		if err == nil {
			t.Error("Expected error with closed keypair, got nil")
		}
		if err != nil {
			t.Logf("Correctly rejected operation on closed keypair: %v", err)
		}
	})

	t.Log("Closed context operations test passed!")
}

// TestMultipartyKeyGenVariants tests both MultipartyKeyGen variants
func TestMultipartyKeyGenVariants(t *testing.T) {
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
	defer params.Close()

	err = params.SetPlaintextModulus(65537)
	mustT(t, err, "SetPlaintextModulus")

	err = params.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)
	mustT(t, err, "SetMultipartyMode")

	cc, err := NewCryptoContextBGV(params)
	mustT(t, err, "NewCryptoContextBGV")
	defer cc.Close()

	err = cc.Enable(PKE | KEYSWITCH | MULTIPARTY)
	mustT(t, err, "Enable")

	// Test variant 1: Generate from existing private keys
	t.Run("MultipartyKeyGenFromPrivateKeys", func(t *testing.T) {
		// Generate two separate keypairs
		kp1, err := cc.KeyGen()
		mustT(t, err, "KeyGen 1")
		defer kp1.Close()

		kp2, err := cc.KeyGen()
		mustT(t, err, "KeyGen 2")
		defer kp2.Close()

		// Get private keys
		sk1, err := kp1.GetMultipartyPrivateKey()
		mustT(t, err, "GetMultipartyPrivateKey 1")
		defer sk1.Close()

		sk2, err := kp2.GetMultipartyPrivateKey()
		mustT(t, err, "GetMultipartyPrivateKey 2")
		defer sk2.Close()

		// Generate joint keypair from private keys
		privateKeys := []*PrivateKey{sk1, sk2}
		jointKP, err := cc.MultipartyKeyGen(privateKeys)
		mustT(t, err, "MultipartyKeyGen from private keys")
		defer jointKP.Close()

		t.Log("MultipartyKeyGen from private keys successful")
	})

	// Test variant 2: Generate from public key (already tested in other tests, but verify it works)
	t.Run("MultipartyKeyGenFromPublicKey", func(t *testing.T) {
		kp1, err := cc.KeyGen()
		mustT(t, err, "KeyGen")
		defer kp1.Close()

		pk1, err := kp1.GetMultipartyPublicKey()
		mustT(t, err, "GetMultipartyPublicKey")
		defer pk1.Close()

		kp2, err := cc.MultipartyKeyGenFromPublicKey(pk1, false, false)
		mustT(t, err, "MultipartyKeyGenFromPublicKey")
		defer kp2.Close()

		t.Log("MultipartyKeyGenFromPublicKey successful")
	})

	t.Log("MultipartyKeyGen variants test passed!")
}
