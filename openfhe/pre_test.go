package openfhe

import (
	"math"
	"testing"
)

// TestPRE_BFV tests Proxy Re-Encryption with BFV scheme
func TestPRE_BFV(t *testing.T) {
	t.Helper()

	// Setup BFV parameters
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	defer params.Close()

	mustT(t, params.SetPlaintextModulus(65537), "SetPlaintextModulus")
	mustT(t, params.SetMultiplicativeDepth(2), "SetMultiplicativeDepth")

	// Generate crypto context
	cc, err := NewCryptoContextBFV(params)
	mustT(t, err, "NewCryptoContextBFV")
	defer cc.Close()

	// Enable features including PRE
	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(PRE), "Enable PRE")

	// Generate keys for Alice
	aliceKeys, err := cc.KeyGen()
	mustT(t, err, "KeyGen for Alice")
	defer aliceKeys.Close()

	// Generate keys for Bob
	bobKeys, err := cc.KeyGen()
	mustT(t, err, "KeyGen for Bob")
	defer bobKeys.Close()

	// Generate re-encryption key from Alice to Bob
	reencryptionKey, err := cc.ReKeyGen(aliceKeys, bobKeys)
	mustT(t, err, "ReKeyGen")
	defer reencryptionKey.Close()

	// Create plaintext with Alice's data
	vectorSize := 16
	aliceData := make([]int64, vectorSize)
	for i := range aliceData {
		aliceData[i] = int64(i + 1)
	}

	plaintext, err := cc.MakePackedPlaintext(aliceData)
	mustT(t, err, "MakePackedPlaintext")
	defer plaintext.Close()

	// Alice encrypts her data
	ciphertext, err := cc.Encrypt(aliceKeys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	// Verify Alice can decrypt her own data
	decryptedByAlice, err := cc.Decrypt(aliceKeys, ciphertext)
	mustT(t, err, "Decrypt by Alice")
	defer decryptedByAlice.Close()

	resultAlice, err := decryptedByAlice.GetPackedValue()
	mustT(t, err, "GetPackedValue for Alice")

	for i := 0; i < vectorSize; i++ {
		if resultAlice[i] != aliceData[i] {
			t.Errorf("Alice decryption mismatch at index %d: expected %d, got %d",
				i, aliceData[i], resultAlice[i])
		}
	}

	// Re-encrypt the ciphertext from Alice's key to Bob's key
	reencryptedCiphertext, err := cc.ReEncrypt(ciphertext, reencryptionKey)
	mustT(t, err, "ReEncrypt")
	defer reencryptedCiphertext.Close()

	// Bob decrypts the re-encrypted ciphertext
	decryptedByBob, err := cc.Decrypt(bobKeys, reencryptedCiphertext)
	mustT(t, err, "Decrypt by Bob")
	defer decryptedByBob.Close()

	resultBob, err := decryptedByBob.GetPackedValue()
	mustT(t, err, "GetPackedValue for Bob")

	// Verify Bob gets the same data as Alice
	for i := 0; i < vectorSize; i++ {
		if resultBob[i] != aliceData[i] {
			t.Errorf("Bob decryption mismatch at index %d: expected %d, got %d",
				i, aliceData[i], resultBob[i])
		}
	}

	t.Logf("PRE BFV Test: Alice's data successfully re-encrypted and decrypted by Bob")
}

// TestPRE_BGV tests Proxy Re-Encryption with BGV scheme
func TestPRE_BGV(t *testing.T) {
	t.Helper()

	// Setup BGV parameters
	params, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
	defer params.Close()

	mustT(t, params.SetPlaintextModulus(65537), "SetPlaintextModulus")
	mustT(t, params.SetMultiplicativeDepth(2), "SetMultiplicativeDepth")

	// Generate crypto context
	cc, err := NewCryptoContextBGV(params)
	mustT(t, err, "NewCryptoContextBGV")
	defer cc.Close()

	// Enable features including PRE
	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(PRE), "Enable PRE")

	// Generate keys for Alice
	aliceKeys, err := cc.KeyGen()
	mustT(t, err, "KeyGen for Alice")
	defer aliceKeys.Close()

	// Generate keys for Bob
	bobKeys, err := cc.KeyGen()
	mustT(t, err, "KeyGen for Bob")
	defer bobKeys.Close()

	// Generate re-encryption key from Alice to Bob
	reencryptionKey, err := cc.ReKeyGen(aliceKeys, bobKeys)
	mustT(t, err, "ReKeyGen")
	defer reencryptionKey.Close()

	// Create plaintext with Alice's data
	vectorSize := 16
	aliceData := make([]int64, vectorSize)
	for i := range aliceData {
		aliceData[i] = int64(i * 10)
	}

	plaintext, err := cc.MakePackedPlaintext(aliceData)
	mustT(t, err, "MakePackedPlaintext")
	defer plaintext.Close()

	// Alice encrypts her data
	ciphertext, err := cc.Encrypt(aliceKeys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	// Re-encrypt the ciphertext from Alice's key to Bob's key
	reencryptedCiphertext, err := cc.ReEncrypt(ciphertext, reencryptionKey)
	mustT(t, err, "ReEncrypt")
	defer reencryptedCiphertext.Close()

	// Bob decrypts the re-encrypted ciphertext
	decryptedByBob, err := cc.Decrypt(bobKeys, reencryptedCiphertext)
	mustT(t, err, "Decrypt by Bob")
	defer decryptedByBob.Close()

	resultBob, err := decryptedByBob.GetPackedValue()
	mustT(t, err, "GetPackedValue for Bob")

	// Verify Bob gets the same data as Alice
	for i := 0; i < vectorSize; i++ {
		if resultBob[i] != aliceData[i] {
			t.Errorf("Bob decryption mismatch at index %d: expected %d, got %d",
				i, aliceData[i], resultBob[i])
		}
	}

	t.Logf("PRE BGV Test: Alice's data successfully re-encrypted and decrypted by Bob")
}

// TestPRE_CKKS tests Proxy Re-Encryption with CKKS scheme
func TestPRE_CKKS(t *testing.T) {
	t.Helper()

	// Setup CKKS parameters
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(3), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetBatchSize(8), "SetBatchSize")

	// Generate crypto context
	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	// Enable features including PRE
	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(PRE), "Enable PRE")

	// Generate keys for Alice
	aliceKeys, err := cc.KeyGen()
	mustT(t, err, "KeyGen for Alice")
	defer aliceKeys.Close()

	// Generate keys for Bob
	bobKeys, err := cc.KeyGen()
	mustT(t, err, "KeyGen for Bob")
	defer bobKeys.Close()

	// Generate re-encryption key from Alice to Bob
	reencryptionKey, err := cc.ReKeyGen(aliceKeys, bobKeys)
	mustT(t, err, "ReKeyGen")
	defer reencryptionKey.Close()

	// Create plaintext with Alice's data
	aliceData := []float64{1.0, 2.5, 3.75, 4.125, 5.5, 6.25, 7.0, 8.5}

	plaintext, err := cc.MakeCKKSPackedPlaintext(aliceData)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	// Alice encrypts her data
	ciphertext, err := cc.Encrypt(aliceKeys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	// Verify Alice can decrypt her own data
	decryptedByAlice, err := cc.Decrypt(aliceKeys, ciphertext)
	mustT(t, err, "Decrypt by Alice")
	defer decryptedByAlice.Close()

	resultAlice, err := decryptedByAlice.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue for Alice")

	const tolerance = 0.01
	for i := 0; i < len(aliceData); i++ {
		diff := math.Abs(resultAlice[i] - aliceData[i])
		if diff > tolerance {
			t.Errorf("Alice decryption mismatch at index %d: expected %.4f, got %.4f (diff %.4f)",
				i, aliceData[i], resultAlice[i], diff)
		}
	}

	// Re-encrypt the ciphertext from Alice's key to Bob's key
	reencryptedCiphertext, err := cc.ReEncrypt(ciphertext, reencryptionKey)
	mustT(t, err, "ReEncrypt")
	defer reencryptedCiphertext.Close()

	// Bob decrypts the re-encrypted ciphertext
	decryptedByBob, err := cc.Decrypt(bobKeys, reencryptedCiphertext)
	mustT(t, err, "Decrypt by Bob")
	defer decryptedByBob.Close()

	resultBob, err := decryptedByBob.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue for Bob")

	// Verify Bob gets the same data as Alice (within tolerance)
	for i := 0; i < len(aliceData); i++ {
		diff := math.Abs(resultBob[i] - aliceData[i])
		if diff > tolerance {
			t.Errorf("Bob decryption mismatch at index %d: expected %.4f, got %.4f (diff %.4f)",
				i, aliceData[i], resultBob[i], diff)
		}
	}

	t.Logf("PRE CKKS Test: Alice's data successfully re-encrypted and decrypted by Bob")
}

// TestPRE_MultipleReencryptions tests chaining re-encryptions (Alice → Bob → Charlie)
func TestPRE_MultipleReencryptions(t *testing.T) {
	t.Helper()

	// Setup BFV parameters
	params, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	defer params.Close()

	mustT(t, params.SetPlaintextModulus(65537), "SetPlaintextModulus")
	mustT(t, params.SetMultiplicativeDepth(3), "SetMultiplicativeDepth")

	// Generate crypto context
	cc, err := NewCryptoContextBFV(params)
	mustT(t, err, "NewCryptoContextBFV")
	defer cc.Close()

	// Enable features including PRE
	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(PRE), "Enable PRE")

	// Generate keys for Alice, Bob, and Charlie
	aliceKeys, err := cc.KeyGen()
	mustT(t, err, "KeyGen for Alice")
	defer aliceKeys.Close()

	bobKeys, err := cc.KeyGen()
	mustT(t, err, "KeyGen for Bob")
	defer bobKeys.Close()

	charlieKeys, err := cc.KeyGen()
	mustT(t, err, "KeyGen for Charlie")
	defer charlieKeys.Close()

	// Generate re-encryption keys
	reencryptionKeyAliceToBob, err := cc.ReKeyGen(aliceKeys, bobKeys)
	mustT(t, err, "ReKeyGen Alice to Bob")
	defer reencryptionKeyAliceToBob.Close()

	reencryptionKeyBobToCharlie, err := cc.ReKeyGen(bobKeys, charlieKeys)
	mustT(t, err, "ReKeyGen Bob to Charlie")
	defer reencryptionKeyBobToCharlie.Close()

	// Create plaintext with Alice's data
	aliceData := []int64{100, 200, 300, 400}

	plaintext, err := cc.MakePackedPlaintext(aliceData)
	mustT(t, err, "MakePackedPlaintext")
	defer plaintext.Close()

	// Alice encrypts her data
	ciphertext, err := cc.Encrypt(aliceKeys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	// Re-encrypt from Alice to Bob
	reencryptedToBob, err := cc.ReEncrypt(ciphertext, reencryptionKeyAliceToBob)
	mustT(t, err, "ReEncrypt to Bob")
	defer reencryptedToBob.Close()

	// Verify Bob can decrypt
	decryptedByBob, err := cc.Decrypt(bobKeys, reencryptedToBob)
	mustT(t, err, "Decrypt by Bob")
	defer decryptedByBob.Close()

	resultBob, err := decryptedByBob.GetPackedValue()
	mustT(t, err, "GetPackedValue for Bob")

	for i := 0; i < len(aliceData); i++ {
		if resultBob[i] != aliceData[i] {
			t.Errorf("Bob decryption mismatch at index %d: expected %d, got %d",
				i, aliceData[i], resultBob[i])
		}
	}

	// Re-encrypt from Bob to Charlie
	reencryptedToCharlie, err := cc.ReEncrypt(reencryptedToBob, reencryptionKeyBobToCharlie)
	mustT(t, err, "ReEncrypt to Charlie")
	defer reencryptedToCharlie.Close()

	// Verify Charlie can decrypt
	decryptedByCharlie, err := cc.Decrypt(charlieKeys, reencryptedToCharlie)
	mustT(t, err, "Decrypt by Charlie")
	defer decryptedByCharlie.Close()

	resultCharlie, err := decryptedByCharlie.GetPackedValue()
	mustT(t, err, "GetPackedValue for Charlie")

	for i := 0; i < len(aliceData); i++ {
		if resultCharlie[i] != aliceData[i] {
			t.Errorf("Charlie decryption mismatch at index %d: expected %d, got %d",
				i, aliceData[i], resultCharlie[i])
		}
	}

	t.Logf("PRE Multiple Reencryptions Test: Alice → Bob → Charlie successful")
}
