package openfhe

import (
	"math"
	"testing"
)

// --- Helper Functions ---
func slicesEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func slicesApproxEqual(a, b []float64, tolerance float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if math.Abs(v-b[i]) > tolerance {
			return false
		}
	}
	return true
}

// Helper to set up a basic BFV context and keys for integer tests
func setupBFVContextAndKeys(t *testing.T) (*CryptoContext, *KeyPair) {
	parameters := NewParamsBFVrns()
	parameters.SetPlaintextModulus(65537)
	parameters.SetMultiplicativeDepth(2)
	cc := NewCryptoContextBFV(parameters)
	cc.Enable(PKE)
	cc.Enable(KEYSWITCH)
	cc.Enable(LEVELEDSHE)
	keys := cc.KeyGen()
	cc.EvalMultKeyGen(keys)
	return cc, keys
}

// Helper to set up a basic BGV context and keys for integer tests
func setupBGVContextAndKeys(t *testing.T) (*CryptoContext, *KeyPair) {
	parameters := NewParamsBGVrns()
	parameters.SetPlaintextModulus(65537)
	parameters.SetMultiplicativeDepth(2)
	cc := NewCryptoContextBGV(parameters)
	cc.Enable(PKE)
	cc.Enable(KEYSWITCH)
	cc.Enable(LEVELEDSHE)
	keys := cc.KeyGen()
	cc.EvalMultKeyGen(keys)
	return cc, keys
}

// Helper to set up a basic CKKS context and keys for real number tests
func setupCKKSContextAndKeys(t *testing.T) (*CryptoContext, *KeyPair) {
	scalingModSize := 50
	batchSize := 8
	multDepth := 1

	parameters := NewParamsCKKSRNS()
	parameters.SetMultiplicativeDepth(multDepth)
	parameters.SetScalingModSize(scalingModSize)
	parameters.SetBatchSize(batchSize)
	cc := NewCryptoContextCKKS(parameters)
	cc.Enable(PKE)
	cc.Enable(KEYSWITCH)
	cc.Enable(LEVELEDSHE)
	keys := cc.KeyGen()
	cc.EvalMultKeyGen(keys)
	return cc, keys
}

// --- BFV Tests ---

func TestBFVEncryptDecryptPacked(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := cc.MakePackedPlaintext(vectorOfInts)
	ciphertext := cc.Encrypt(keys, plaintext)
	plaintextDec := cc.Decrypt(keys, ciphertext)

	vecLen := len(vectorOfInts)
	if !slicesEqual(plaintextDec.GetPackedValue()[:vecLen], vectorOfInts) {
		t.Errorf("BFV Encrypt/Decrypt mismatch. Expected %v, Got %v", vectorOfInts, plaintextDec.GetPackedValue()[:vecLen])
	}
}

func TestBFVPackedAdd(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := cc.MakePackedPlaintext(vectorOfInts)
	ciphertext := cc.Encrypt(keys, plaintext)
	ctAdd := cc.EvalAdd(ciphertext, ciphertext)
	ptAdd := cc.Decrypt(keys, ctAdd)

	vecLen := len(vectorOfInts)
	addExpected := []int64{2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24}
	if !slicesEqual(ptAdd.GetPackedValue()[:vecLen], addExpected) {
		t.Errorf("BFV Packed Add failed. Expected %v, Got %v", addExpected, ptAdd.GetPackedValue()[:vecLen])
	}
}

func TestBFVPackedMult(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := cc.MakePackedPlaintext(vectorOfInts)
	ciphertext := cc.Encrypt(keys, plaintext)
	ctMult := cc.EvalMult(ciphertext, ciphertext)
	ptMult := cc.Decrypt(keys, ctMult)

	vecLen := len(vectorOfInts)
	mulExpected := []int64{1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144}
	if !slicesEqual(ptMult.GetPackedValue()[:vecLen], mulExpected) {
		t.Errorf("BFV Packed Mult failed. Expected %v, Got %v", mulExpected, ptMult.GetPackedValue()[:vecLen])
	}
}

func TestBFVPackedRotate(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	// Rotation keys needed for specific indices
	rotIndices := []int32{1, -2}
	cc.EvalRotateKeyGen(keys, rotIndices)

	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := cc.MakePackedPlaintext(vectorOfInts)
	ciphertext := cc.Encrypt(keys, plaintext)

	ctRot1 := cc.EvalRotate(ciphertext, 1)
	ptRot1 := cc.Decrypt(keys, ctRot1)
	ctRotNeg2 := cc.EvalRotate(ciphertext, -2)
	ptRotNeg2 := cc.Decrypt(keys, ctRotNeg2)

	vecLen := len(vectorOfInts)
	// Adjust expected results based on packed rotation behavior
	rot1Expected := []int64{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0}
	rotNeg2Expected := []int64{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	ptRot1.SetLength(vecLen) // Set length for correct comparison
	ptRotNeg2.SetLength(vecLen)

	if !slicesEqual(ptRot1.GetPackedValue(), rot1Expected) {
		t.Errorf("BFV Rotate(1) failed. Expected %v, Got %v", rot1Expected, ptRot1.GetPackedValue())
	}
	if !slicesEqual(ptRotNeg2.GetPackedValue(), rotNeg2Expected) {
		t.Errorf("BFV Rotate(-2) failed. Expected %v, Got %v", rotNeg2Expected, ptRotNeg2.GetPackedValue())
	}
}

// --- BGV Tests ---

func TestBGVEncryptDecryptPacked(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := cc.MakePackedPlaintext(vectorOfInts)
	ciphertext := cc.Encrypt(keys, plaintext)
	plaintextDec := cc.Decrypt(keys, ciphertext)

	vecLen := len(vectorOfInts)
	if !slicesEqual(plaintextDec.GetPackedValue()[:vecLen], vectorOfInts) {
		t.Errorf("BGV Encrypt/Decrypt mismatch. Expected %v, Got %v", vectorOfInts, plaintextDec.GetPackedValue()[:vecLen])
	}
}

func TestBGVPackedAdd(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	v1 := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	v2 := []int64{3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	v3 := []int64{1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12}
	pt1 := cc.MakePackedPlaintext(v1)
	pt2 := cc.MakePackedPlaintext(v2)
	pt3 := cc.MakePackedPlaintext(v3)
	ct1 := cc.Encrypt(keys, pt1)
	ct2 := cc.Encrypt(keys, pt2)
	ct3 := cc.Encrypt(keys, pt3)

	ctAdd12 := cc.EvalAdd(ct1, ct2)
	ctAddResult := cc.EvalAdd(ctAdd12, ct3)
	ptAddResult := cc.Decrypt(keys, ctAddResult)

	vecLen := len(v1)
	addExpected := make([]int64, vecLen)
	ptMod := int64(65537)
	for i := 0; i < vecLen; i++ {
		addExpected[i] = (v1[i] + v2[i] + v3[i]) % ptMod
	}

	if !slicesEqual(ptAddResult.GetPackedValue()[:vecLen], addExpected) {
		t.Errorf("BGV Packed Add failed. Expected %v, Got %v", addExpected, ptAddResult.GetPackedValue()[:vecLen])
	}
}

func TestBGVPackedMult(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	v1 := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	v2 := []int64{3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	v3 := []int64{1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12}
	pt1 := cc.MakePackedPlaintext(v1)
	pt2 := cc.MakePackedPlaintext(v2)
	pt3 := cc.MakePackedPlaintext(v3)
	ct1 := cc.Encrypt(keys, pt1)
	ct2 := cc.Encrypt(keys, pt2)
	ct3 := cc.Encrypt(keys, pt3)

	ctMult12 := cc.EvalMult(ct1, ct2)
	ctMultResult := cc.EvalMult(ctMult12, ct3)
	ptMultResult := cc.Decrypt(keys, ctMultResult)

	vecLen := len(v1)
	mulExpected := make([]int64, vecLen)
	ptMod := int64(65537)
	for i := 0; i < vecLen; i++ {
		mulExpected[i] = (v1[i] * v2[i] * v3[i]) % ptMod
	}

	if !slicesEqual(ptMultResult.GetPackedValue()[:vecLen], mulExpected) {
		t.Errorf("BGV Packed Mult failed. Expected %v, Got %v", mulExpected, ptMultResult.GetPackedValue()[:vecLen])
	}
}

func TestBGVPackedRotate(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	// Rotation keys needed for specific indices
	rotIndices := []int32{1, 2, -1, -2}
	cc.EvalRotateKeyGen(keys, rotIndices)

	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := cc.MakePackedPlaintext(vectorOfInts)
	ciphertext := cc.Encrypt(keys, plaintext)

	ctRot1 := cc.EvalRotate(ciphertext, 1)
	ptRot1 := cc.Decrypt(keys, ctRot1)
	ctRot2 := cc.EvalRotate(ciphertext, 2)
	ptRot2 := cc.Decrypt(keys, ctRot2)
	ctRotNeg1 := cc.EvalRotate(ciphertext, -1)
	ptRotNeg1 := cc.Decrypt(keys, ctRotNeg1)
	ctRotNeg2 := cc.EvalRotate(ciphertext, -2)
	ptRotNeg2 := cc.Decrypt(keys, ctRotNeg2)

	vecLen := len(vectorOfInts)
	rot1Expected := []int64{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0}
	rot2Expected := []int64{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0}
	rotNeg1Expected := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	rotNeg2Expected := []int64{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	ptRot1.SetLength(vecLen)
	ptRot2.SetLength(vecLen)
	ptRotNeg1.SetLength(vecLen)
	ptRotNeg2.SetLength(vecLen)

	if !slicesEqual(ptRot1.GetPackedValue(), rot1Expected) {
		t.Errorf("BGV Rotate(1) failed. Expected %v, Got %v", rot1Expected, ptRot1.GetPackedValue())
	}
	if !slicesEqual(ptRot2.GetPackedValue(), rot2Expected) {
		t.Errorf("BGV Rotate(2) failed. Expected %v, Got %v", rot2Expected, ptRot2.GetPackedValue())
	}
	if !slicesEqual(ptRotNeg1.GetPackedValue(), rotNeg1Expected) {
		t.Errorf("BGV Rotate(-1) failed. Expected %v, Got %v", rotNeg1Expected, ptRotNeg1.GetPackedValue())
	}
	if !slicesEqual(ptRotNeg2.GetPackedValue(), rotNeg2Expected) {
		t.Errorf("BGV Rotate(-2) failed. Expected %v, Got %v", rotNeg2Expected, ptRotNeg2.GetPackedValue())
	}
}

// --- CKKS Tests ---

func TestCKKSEncryptDecryptPacked(t *testing.T) {
	cc, keys := setupCKKSContextAndKeys(t)
	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	ciphertext := cc.Encrypt(keys, plaintext)
	plaintextDec := cc.Decrypt(keys, ciphertext)

	batchSize := len(vectorOfDoubles) // Assuming batchSize matches vector length
	tolerance := 0.0001
	if !slicesApproxEqual(plaintextDec.GetRealPackedValue()[:batchSize], vectorOfDoubles, tolerance) {
		t.Errorf("CKKS Encrypt/Decrypt mismatch. Expected ~%v, Got %v", vectorOfDoubles, plaintextDec.GetRealPackedValue()[:batchSize])
	}
}

func TestCKKSPackedAdd(t *testing.T) {
	cc, keys := setupCKKSContextAndKeys(t)
	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	ciphertext := cc.Encrypt(keys, plaintext)
	ctAdd := cc.EvalAdd(ciphertext, ciphertext)
	ptAdd := cc.Decrypt(keys, ctAdd)

	batchSize := len(vectorOfDoubles)
	addExpected := []float64{2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, 16.0}
	tolerance := 0.0001
	if !slicesApproxEqual(ptAdd.GetRealPackedValue()[:batchSize], addExpected, tolerance) {
		t.Errorf("CKKS Packed Add failed. Expected ~%v, Got %v", addExpected, ptAdd.GetRealPackedValue()[:batchSize])
	}
}

func TestCKKSPackedSub(t *testing.T) {
	cc, keys := setupCKKSContextAndKeys(t)
	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	ciphertext := cc.Encrypt(keys, plaintext)
	ctSub := cc.EvalSub(ciphertext, ciphertext)
	ptSub := cc.Decrypt(keys, ctSub)

	batchSize := len(vectorOfDoubles)
	subExpected := []float64{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}
	tolerance := 0.0001
	if !slicesApproxEqual(ptSub.GetRealPackedValue()[:batchSize], subExpected, tolerance) {
		t.Errorf("CKKS Packed Sub failed. Expected ~%v, Got %v", subExpected, ptSub.GetRealPackedValue()[:batchSize])
	}
}

func TestCKKSPackedMult(t *testing.T) {
	cc, keys := setupCKKSContextAndKeys(t)
	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	ciphertext := cc.Encrypt(keys, plaintext)
	ctMult := cc.EvalMult(ciphertext, ciphertext)
	ctMultRescaled := cc.Rescale(ctMult) // Rescale needed after multiplication
	ptMult := cc.Decrypt(keys, ctMultRescaled)

	batchSize := len(vectorOfDoubles)
	mulExpected := []float64{1.0, 4.0, 9.0, 16.0, 25.0, 36.0, 49.0, 64.0}
	tolerance := 0.0001
	if !slicesApproxEqual(ptMult.GetRealPackedValue()[:batchSize], mulExpected, tolerance) {
		t.Errorf("CKKS Packed Mult failed. Expected ~%v, Got %v", mulExpected, ptMult.GetRealPackedValue()[:batchSize])
	}
}

// --- Serialization Tests ---

func TestSerializationRoundTrip(t *testing.T) {
	// 1. Setup Original
	ccOrig, keysOrig := setupBFVContextAndKeys(t)
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintextOrig := ccOrig.MakePackedPlaintext(vectorOfInts)
	ciphertextOrig := ccOrig.Encrypt(keysOrig, plaintextOrig)

	// 2. Serialize
	ccSerial, err := SerializeCryptoContextToString(ccOrig)
	if err != nil {
		t.Fatalf("CryptoContext serialization failed: %v", err)
	}
	pkSerial, err := SerializePublicKeyToString(keysOrig)
	if err != nil {
		t.Fatalf("PublicKey serialization failed: %v", err)
	}
	skSerial, err := SerializePrivateKeyToString(keysOrig)
	if err != nil {
		t.Fatalf("PrivateKey serialization failed: %v", err)
	}
	ctSerial, err := SerializeCiphertextToString(ciphertextOrig)
	if err != nil {
		t.Fatalf("Ciphertext serialization failed: %v", err)
	}

	// Nullify originals
	ccOrig = nil
	keysOrig = nil
	ciphertextOrig = nil

	// 3. Deserialize
	ccLoaded := DeserializeCryptoContextFromString(ccSerial)
	if ccLoaded == nil {
		t.Fatalf("CryptoContext deserialization failed")
	}
	kpPublic := DeserializePublicKeyFromString(pkSerial)
	if kpPublic == nil {
		t.Fatalf("PublicKey deserialization failed")
	}
	kpPrivate := DeserializePrivateKeyFromString(skSerial)
	if kpPrivate == nil {
		t.Fatalf("PrivateKey deserialization failed")
	}
	keysLoaded := NewKeyPair()
	keysLoaded.SetPublicKey(kpPublic.GetPublicKey())
	keysLoaded.SetPrivateKey(kpPrivate.GetPrivateKey())
	ctLoaded := DeserializeCiphertextFromString(ctSerial)
	if ctLoaded == nil {
		t.Fatalf("Ciphertext deserialization failed")
	}

	// 4. Decrypt and Verify
	plaintextLoaded := ccLoaded.Decrypt(keysLoaded, ctLoaded)
	if plaintextLoaded == nil {
		t.Fatalf("Decryption after round trip deserialization failed")
	}
	vecLen := len(vectorOfInts)
	result := plaintextLoaded.GetPackedValue()[:vecLen]
	if !slicesEqual(result, vectorOfInts) {
		t.Errorf("Round Trip: Decryption mismatch. Expected %v, Got %v", vectorOfInts, result)
	}
}
