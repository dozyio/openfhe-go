package openfhe

import (
	"testing"
)

// --- Helper Functions ---
// Helper to set up a basic BFV context and keys for integer tests
func setupBFVContextAndKeys(t *testing.T) (*CryptoContext, *KeyPair) {
	parameters, err := NewParamsBFVrns()
	mustT(t, err, "NewParamsBFVrns")
	defer parameters.Close()

	mustT(t, parameters.SetPlaintextModulus(65537), "SetPlaintextModulus")
	mustT(t, parameters.SetMultiplicativeDepth(2), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextBFV(parameters)
	mustT(t, err, "NewCryptoContextBFV")

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")

	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen")
	return cc, keys // Caller must Close cc and keys
}

// Helper to set up a basic BGV context and keys for integer tests
func setupBGVContextAndKeys(t *testing.T) (*CryptoContext, *KeyPair) {
	parameters, err := NewParamsBGVrns()
	mustT(t, err, "NewParamsBGVrns")
	defer parameters.Close()

	mustT(t, parameters.SetPlaintextModulus(65537), "SetPlaintextModulus")
	mustT(t, parameters.SetMultiplicativeDepth(2), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextBGV(parameters)
	mustT(t, err, "NewCryptoContextBGV")

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")

	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen")
	return cc, keys // Caller must Close cc and keys
}

// Helper to set up a basic CKKS context and keys for real number tests
func setupCKKSContextAndKeys(t *testing.T) (*CryptoContext, *KeyPair) {
	scalingModSize := 50
	batchSize := 8
	multDepth := 1

	parameters, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer parameters.Close()

	mustT(t, parameters.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")
	mustT(t, parameters.SetScalingModSize(scalingModSize), "SetScalingModSize")
	mustT(t, parameters.SetBatchSize(batchSize), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(parameters)
	mustT(t, err, "NewCryptoContextCKKS")

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")

	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen")
	return cc, keys // Caller must Close cc and keys
}

// --- BFV Tests ---

func TestBFVEncryptDecryptPacked(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext, err := cc.MakePackedPlaintext(vectorOfInts)
	mustT(t, err, "MakePackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	plaintextDec, err := cc.Decrypt(keys, ciphertext)
	mustT(t, err, "Decrypt")
	defer plaintextDec.Close()

	vecLen := len(vectorOfInts)
	result, err := plaintextDec.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	if !slicesEqual(result[:vecLen], vectorOfInts) {
		t.Errorf("BFV Encrypt/Decrypt mismatch. Expected %v, Got %v", vectorOfInts, result[:vecLen])
	}
}

func TestBFVPackedAdd(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext, err := cc.MakePackedPlaintext(vectorOfInts)
	mustT(t, err, "MakePackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	ctAdd, err := cc.EvalAdd(ciphertext, ciphertext)
	mustT(t, err, "EvalAdd")
	defer ctAdd.Close()

	ptAdd, err := cc.Decrypt(keys, ctAdd)
	mustT(t, err, "Decrypt")
	defer ptAdd.Close()

	vecLen := len(vectorOfInts)
	addExpected := []int64{2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24}
	result, err := ptAdd.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	if !slicesEqual(result[:vecLen], addExpected) {
		t.Errorf("BFV Packed Add failed. Expected %v, Got %v", addExpected, result[:vecLen])
	}
}

func TestBFVPackedMult(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext, err := cc.MakePackedPlaintext(vectorOfInts)
	mustT(t, err, "MakePackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	ctMult, err := cc.EvalMult(ciphertext, ciphertext)
	mustT(t, err, "EvalMult")
	defer ctMult.Close()

	ptMult, err := cc.Decrypt(keys, ctMult)
	mustT(t, err, "Decrypt")
	defer ptMult.Close()

	vecLen := len(vectorOfInts)
	mulExpected := []int64{1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144}
	result, err := ptMult.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	if !slicesEqual(result[:vecLen], mulExpected) {
		t.Errorf("BFV Packed Mult failed. Expected %v, Got %v", mulExpected, result[:vecLen])
	}
}

func TestBFVPackedRotate(t *testing.T) {
	cc, keys := setupBFVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	// Rotation keys needed for specific indices
	rotIndices := []int32{1, -2}
	mustT(t, cc.EvalRotateKeyGen(keys, rotIndices), "EvalRotateKeyGen")

	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext, err := cc.MakePackedPlaintext(vectorOfInts)
	mustT(t, err, "MakePackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	ctRot1, err := cc.EvalRotate(ciphertext, 1)
	mustT(t, err, "EvalRotate 1")
	defer ctRot1.Close()
	ptRot1, err := cc.Decrypt(keys, ctRot1)
	mustT(t, err, "Decrypt ctRot1")
	defer ptRot1.Close()

	ctRotNeg2, err := cc.EvalRotate(ciphertext, -2)
	mustT(t, err, "EvalRotate -2")
	defer ctRotNeg2.Close()
	ptRotNeg2, err := cc.Decrypt(keys, ctRotNeg2)
	mustT(t, err, "Decrypt ctRotNeg2")
	defer ptRotNeg2.Close()

	vecLen := len(vectorOfInts)
	// Adjust expected results based on packed rotation behavior
	rot1Expected := []int64{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0}
	rotNeg2Expected := []int64{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	mustT(t, ptRot1.SetLength(vecLen), "SetLength ptRot1") // Set length for correct comparison
	mustT(t, ptRotNeg2.SetLength(vecLen), "SetLength ptRotNeg2")

	result1, err := ptRot1.GetPackedValue()
	mustT(t, err, "GetPackedValue ptRot1")
	resultNeg2, err := ptRotNeg2.GetPackedValue()
	mustT(t, err, "GetPackedValue ptRotNeg2")

	if !slicesEqual(result1, rot1Expected) {
		t.Errorf("BFV Rotate(1) failed. Expected %v, Got %v", rot1Expected, result1)
	}
	if !slicesEqual(resultNeg2, rotNeg2Expected) {
		t.Errorf("BFV Rotate(-2) failed. Expected %v, Got %v", rotNeg2Expected, resultNeg2)
	}
}

// --- BGV Tests ---

func TestBGVEncryptDecryptPacked(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext, err := cc.MakePackedPlaintext(vectorOfInts)
	mustT(t, err, "MakePackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	plaintextDec, err := cc.Decrypt(keys, ciphertext)
	mustT(t, err, "Decrypt")
	defer plaintextDec.Close()

	vecLen := len(vectorOfInts)
	result, err := plaintextDec.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	if !slicesEqual(result[:vecLen], vectorOfInts) {
		t.Errorf("BGV Encrypt/Decrypt mismatch. Expected %v, Got %v", vectorOfInts, result[:vecLen])
	}
}

func TestBGVPackedAdd(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	v1 := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	v2 := []int64{3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	v3 := []int64{1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12}

	pt1, err := cc.MakePackedPlaintext(v1)
	mustT(t, err, "Make pt1")
	defer pt1.Close()
	pt2, err := cc.MakePackedPlaintext(v2)
	mustT(t, err, "Make pt2")
	defer pt2.Close()
	pt3, err := cc.MakePackedPlaintext(v3)
	mustT(t, err, "Make pt3")
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

	ctAdd12, err := cc.EvalAdd(ct1, ct2)
	mustT(t, err, "EvalAdd ct1+ct2")
	defer ctAdd12.Close()
	ctAddResult, err := cc.EvalAdd(ctAdd12, ct3)
	mustT(t, err, "EvalAdd ctAdd12+ct3")
	defer ctAddResult.Close()

	ptAddResult, err := cc.Decrypt(keys, ctAddResult)
	mustT(t, err, "Decrypt")
	defer ptAddResult.Close()

	vecLen := len(v1)
	addExpected := make([]int64, vecLen)
	ptMod := int64(65537)
	for i := 0; i < vecLen; i++ {
		addExpected[i] = (v1[i] + v2[i] + v3[i]) % ptMod
	}

	result, err := ptAddResult.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	if !slicesEqual(result[:vecLen], addExpected) {
		t.Errorf("BGV Packed Add failed. Expected %v, Got %v", addExpected, result[:vecLen])
	}
}

func TestBGVPackedMult(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	v1 := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	v2 := []int64{3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	v3 := []int64{1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12}

	pt1, err := cc.MakePackedPlaintext(v1)
	mustT(t, err, "Make pt1")
	defer pt1.Close()
	pt2, err := cc.MakePackedPlaintext(v2)
	mustT(t, err, "Make pt2")
	defer pt2.Close()
	pt3, err := cc.MakePackedPlaintext(v3)
	mustT(t, err, "Make pt3")
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

	ctMult12, err := cc.EvalMult(ct1, ct2)
	mustT(t, err, "EvalMult ct1*ct2")
	defer ctMult12.Close()
	ctMultResult, err := cc.EvalMult(ctMult12, ct3)
	mustT(t, err, "EvalMult ctMult12*ct3")
	defer ctMultResult.Close()

	ptMultResult, err := cc.Decrypt(keys, ctMultResult)
	mustT(t, err, "Decrypt")
	defer ptMultResult.Close()

	vecLen := len(v1)
	mulExpected := make([]int64, vecLen)
	ptMod := int64(65537)
	for i := 0; i < vecLen; i++ {
		mulExpected[i] = (v1[i] * v2[i] * v3[i]) % ptMod
	}

	result, err := ptMultResult.GetPackedValue()
	mustT(t, err, "GetPackedValue")

	if !slicesEqual(result[:vecLen], mulExpected) {
		t.Errorf("BGV Packed Mult failed. Expected %v, Got %v", mulExpected, result[:vecLen])
	}
}

func TestBGVPackedRotate(t *testing.T) {
	cc, keys := setupBGVContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	// Rotation keys needed for specific indices
	rotIndices := []int32{1, 2, -1, -2}
	mustT(t, cc.EvalRotateKeyGen(keys, rotIndices), "EvalRotateKeyGen")

	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext, err := cc.MakePackedPlaintext(vectorOfInts)
	mustT(t, err, "MakePackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	ctRot1, err := cc.EvalRotate(ciphertext, 1)
	mustT(t, err, "EvalRotate 1")
	defer ctRot1.Close()
	ptRot1, err := cc.Decrypt(keys, ctRot1)
	mustT(t, err, "Decrypt 1")
	defer ptRot1.Close()

	ctRot2, err := cc.EvalRotate(ciphertext, 2)
	mustT(t, err, "EvalRotate 2")
	defer ctRot2.Close()
	ptRot2, err := cc.Decrypt(keys, ctRot2)
	mustT(t, err, "Decrypt 2")
	defer ptRot2.Close()

	ctRotNeg1, err := cc.EvalRotate(ciphertext, -1)
	mustT(t, err, "EvalRotate -1")
	defer ctRotNeg1.Close()
	ptRotNeg1, err := cc.Decrypt(keys, ctRotNeg1)
	mustT(t, err, "Decrypt -1")
	defer ptRotNeg1.Close()

	ctRotNeg2, err := cc.EvalRotate(ciphertext, -2)
	mustT(t, err, "EvalRotate -2")
	defer ctRotNeg2.Close()
	ptRotNeg2, err := cc.Decrypt(keys, ctRotNeg2)
	mustT(t, err, "Decrypt -2")
	defer ptRotNeg2.Close()

	vecLen := len(vectorOfInts)
	rot1Expected := []int64{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0}
	rot2Expected := []int64{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0}
	rotNeg1Expected := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	rotNeg2Expected := []int64{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	mustT(t, ptRot1.SetLength(vecLen), "SetLength 1")
	mustT(t, ptRot2.SetLength(vecLen), "SetLength 2")
	mustT(t, ptRotNeg1.SetLength(vecLen), "SetLength -1")
	mustT(t, ptRotNeg2.SetLength(vecLen), "SetLength -2")

	res1, err := ptRot1.GetPackedValue()
	mustT(t, err, "GetPackedValue 1")
	res2, err := ptRot2.GetPackedValue()
	mustT(t, err, "GetPackedValue 2")
	resNeg1, err := ptRotNeg1.GetPackedValue()
	mustT(t, err, "GetPackedValue -1")
	resNeg2, err := ptRotNeg2.GetPackedValue()
	mustT(t, err, "GetPackedValue -2")

	if !slicesEqual(res1, rot1Expected) {
		t.Errorf("BGV Rotate(1) failed. Expected %v, Got %v", rot1Expected, res1)
	}
	if !slicesEqual(res2, rot2Expected) {
		t.Errorf("BGV Rotate(2) failed. Expected %v, Got %v", rot2Expected, res2)
	}
	if !slicesEqual(resNeg1, rotNeg1Expected) {
		t.Errorf("BGV Rotate(-1) failed. Expected %v, Got %v", rotNeg1Expected, resNeg1)
	}
	if !slicesEqual(resNeg2, rotNeg2Expected) {
		t.Errorf("BGV Rotate(-2) failed. Expected %v, Got %v", rotNeg2Expected, resNeg2)
	}
}

// --- CKKS Tests ---

func TestCKKSEncryptDecryptPacked(t *testing.T) {
	cc, keys := setupCKKSContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext, err := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	plaintextDec, err := cc.Decrypt(keys, ciphertext)
	mustT(t, err, "Decrypt")
	defer plaintextDec.Close()

	batchSize := len(vectorOfDoubles) // Assuming batchSize matches vector length
	tolerance := 0.0001
	result, err := plaintextDec.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	if !slicesApproxEqual(result[:batchSize], vectorOfDoubles, tolerance) {
		t.Errorf("CKKS Encrypt/Decrypt mismatch. Expected ~%v, Got %v", vectorOfDoubles, result[:batchSize])
	}
}

func TestCKKSPackedAdd(t *testing.T) {
	cc, keys := setupCKKSContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext, err := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	ctAdd, err := cc.EvalAdd(ciphertext, ciphertext)
	mustT(t, err, "EvalAdd")
	defer ctAdd.Close()

	ptAdd, err := cc.Decrypt(keys, ctAdd)
	mustT(t, err, "Decrypt")
	defer ptAdd.Close()

	batchSize := len(vectorOfDoubles)
	addExpected := []float64{2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, 16.0}
	tolerance := 0.0001
	result, err := ptAdd.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	if !slicesApproxEqual(result[:batchSize], addExpected, tolerance) {
		t.Errorf("CKKS Packed Add failed. Expected ~%v, Got %v", addExpected, result[:batchSize])
	}
}

func TestCKKSPackedSub(t *testing.T) {
	cc, keys := setupCKKSContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext, err := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	ctSub, err := cc.EvalSub(ciphertext, ciphertext)
	mustT(t, err, "EvalSub")
	defer ctSub.Close()

	ptSub, err := cc.Decrypt(keys, ctSub)
	mustT(t, err, "Decrypt")
	defer ptSub.Close()

	batchSize := len(vectorOfDoubles)
	subExpected := []float64{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}
	tolerance := 0.0001
	result, err := ptSub.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	if !slicesApproxEqual(result[:batchSize], subExpected, tolerance) {
		t.Errorf("CKKS Packed Sub failed. Expected ~%v, Got %v", subExpected, result[:batchSize])
	}
}

func TestCKKSPackedMult(t *testing.T) {
	cc, keys := setupCKKSContextAndKeys(t)
	defer cc.Close()
	defer keys.Close()

	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext, err := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	ctMult, err := cc.EvalMult(ciphertext, ciphertext)
	mustT(t, err, "EvalMult")
	defer ctMult.Close()

	ctMultRescaled, err := cc.Rescale(ctMult) // Rescale needed after multiplication
	mustT(t, err, "Rescale")
	defer ctMultRescaled.Close()

	ptMult, err := cc.Decrypt(keys, ctMultRescaled)
	mustT(t, err, "Decrypt")
	defer ptMult.Close()

	batchSize := len(vectorOfDoubles)
	mulExpected := []float64{1.0, 4.0, 9.0, 16.0, 25.0, 36.0, 49.0, 64.0}
	tolerance := 0.0001
	result, err := ptMult.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	if !slicesApproxEqual(result[:batchSize], mulExpected, tolerance) {
		t.Errorf("CKKS Packed Mult failed. Expected ~%v, Got %v", mulExpected, result[:batchSize])
	}
}

// --- Serialization Tests ---

func TestSerializationRoundTrip(t *testing.T) {
	// 1. Setup Original
	ccOrig, keysOrig := setupBFVContextAndKeys(t)
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintextOrig, err := ccOrig.MakePackedPlaintext(vectorOfInts)
	mustT(t, err, "MakePackedPlaintext orig")
	ciphertextOrig, err := ccOrig.Encrypt(keysOrig, plaintextOrig)
	mustT(t, err, "Encrypt orig")

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

	// Close originals *before* setting to nil
	ccOrig.Close()
	keysOrig.Close()
	plaintextOrig.Close()
	ciphertextOrig.Close()
	ccOrig = nil
	keysOrig = nil
	plaintextOrig = nil
	ciphertextOrig = nil

	// 3. Deserialize
	ccLoaded := DeserializeCryptoContextFromString(ccSerial)
	if ccLoaded == nil {
		t.Fatalf("CryptoContext deserialization failed")
	}
	defer ccLoaded.Close()

	kpPublic := DeserializePublicKeyFromString(pkSerial)
	if kpPublic == nil {
		t.Fatalf("PublicKey deserialization failed")
	}
	defer kpPublic.Close()

	kpPrivate := DeserializePrivateKeyFromString(skSerial)
	if kpPrivate == nil {
		t.Fatalf("PrivateKey deserialization failed")
	}
	defer kpPrivate.Close()

	keysLoaded, err := NewKeyPair()
	mustT(t, err, "NewKeyPair loaded")
	defer keysLoaded.Close()

	pkPtr, err := kpPublic.GetPublicKey()
	mustT(t, err, "GetPublicKey")
	mustT(t, keysLoaded.SetPublicKey(pkPtr), "SetPublicKey")

	skPtr, err := kpPrivate.GetPrivateKey()
	mustT(t, err, "GetPrivateKey")
	mustT(t, keysLoaded.SetPrivateKey(skPtr), "SetPrivateKey")

	ctLoaded := DeserializeCiphertextFromString(ctSerial)
	if ctLoaded == nil {
		t.Fatalf("Ciphertext deserialization failed")
	}
	defer ctLoaded.Close()

	// 4. Decrypt and Verify
	plaintextLoaded, err := ccLoaded.Decrypt(keysLoaded, ctLoaded)
	if err != nil {
		t.Fatalf("Decryption after round trip deserialization failed: %v", err)
	}
	defer plaintextLoaded.Close()

	vecLen := len(vectorOfInts)
	result, err := plaintextLoaded.GetPackedValue()
	mustT(t, err, "GetPackedValue loaded")

	if !slicesEqual(result[:vecLen], vectorOfInts) {
		t.Errorf("Round Trip: Decryption mismatch. Expected %v, Got %v", vectorOfInts, result[:vecLen])
	}
}
