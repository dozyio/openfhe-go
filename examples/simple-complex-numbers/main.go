package main

import (
	"fmt"
	"log"

	"github.com/dozyio/openfhe-go/openfhe"
)

func checkErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

func printComplexVector(name string, vec []complex128, maxLen int) {
	if len(vec) > maxLen {
		vec = vec[:maxLen]
	}
	fmt.Printf("%s: ", name)
	for i, v := range vec {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("(%.6f%+.6fi)", real(v), imag(v))
	}
	fmt.Println()
}

func main() {
	simpleComplexNumbers()
	simpleBootstrappingComplex()
}

func simpleComplexNumbers() {
	fmt.Println("\n=================Simple operations on Complex Numbers=====================")

	// Step 1: Setup CryptoContext
	multDepth := 1
	scaleModSize := 50
	batchSize := 8

	parameters, err := openfhe.NewParamsCKKSRNS()
	checkErr(err, "NewParamsCKKSRNS")
	defer parameters.Close()

	checkErr(parameters.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")
	checkErr(parameters.SetScalingModSize(scaleModSize), "SetScalingModSize")
	checkErr(parameters.SetBatchSize(batchSize), "SetBatchSize")
	checkErr(parameters.SetCKKSDataType(openfhe.CKKS_DATA_TYPE_COMPLEX), "SetCKKSDataType")

	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	checkErr(err, "NewCryptoContextCKKS")
	defer cc.Close()

	checkErr(cc.Enable(openfhe.PKE), "Enable PKE")
	checkErr(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	checkErr(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")

	ringDim := cc.GetRingDimension()
	fmt.Printf("CKKS scheme is using ring dimension %d\n\n", ringDim)

	// Step 2: Key Generation
	keys, err := cc.KeyGen()
	checkErr(err, "KeyGen")
	defer keys.Close()

	checkErr(cc.EvalMultKeyGen(keys), "EvalMultKeyGen")

	// Generate rotation keys
	checkErr(cc.EvalRotateKeyGen(keys, []int32{1, -2}), "EvalRotateKeyGen")

	// Generate conjugation key (automorphism with index 2N - 1)
	indexConj := uint32(2*ringDim - 1)
	checkErr(cc.EvalAutomorphismKeyGen(keys, []uint32{indexConj}), "EvalAutomorphismKeyGen")

	// Step 3: Encoding and encryption of inputs
	x1 := []complex128{
		0.25 + 0.25i, 0.5 + 0.5i, 0.75 + 0.75i, 1.0 + 1.i,
		2.0 + 2.i, 3.0 + 3.i, 4.0 + 4.i, 5.0 + 5.i,
	}
	x2 := []complex128{
		5.0 - 5.0i, 4.0 - 4.i, 3.0 - 3.i, 2.0 - 2.i,
		1.0 - 1.i, 0.75 - 0.75i, 0.5 - 0.5i, 0.25 - 0.25i,
	}

	constComplex := 1.0 - 2.0i
	constComplex2 := 1.0 + 0.5i

	// Encoding as plaintexts
	ptxt1, err := cc.MakeCKKSComplexPackedPlaintext(x1)
	checkErr(err, "MakeCKKSComplexPackedPlaintext x1")
	defer ptxt1.Close()

	ptxt2, err := cc.MakeCKKSComplexPackedPlaintext(x2)
	checkErr(err, "MakeCKKSComplexPackedPlaintext x2")
	defer ptxt2.Close()

	printComplexVector("Input x1", x1, batchSize)
	printComplexVector("Input x2", x2, batchSize)

	// Encrypt the encoded vectors
	c1, err := cc.Encrypt(keys, ptxt1)
	checkErr(err, "Encrypt c1")
	defer c1.Close()

	c2, err := cc.Encrypt(keys, ptxt2)
	checkErr(err, "Encrypt c2")
	defer c2.Close()

	// Step 4: Evaluation

	// Homomorphic addition
	cAdd, err := cc.EvalAdd(c1, c2)
	checkErr(err, "EvalAdd")
	defer cAdd.Close()

	// Homomorphic subtraction
	cSub, err := cc.EvalSub(c1, c2)
	checkErr(err, "EvalSub")
	defer cSub.Close()

	// Homomorphic scalar multiplication
	cScalar, err := cc.EvalMultDouble(c1, 4.0)
	checkErr(err, "EvalMult scalar")
	defer cScalar.Close()

	// Homomorphic multiplication
	cMul, err := cc.EvalMult(c1, c2)
	checkErr(err, "EvalMult")
	defer cMul.Close()

	// Homomorphic rotations
	cRot1, err := cc.EvalRotate(c1, 1)
	checkErr(err, "EvalRotate 1")
	defer cRot1.Close()

	cRot2, err := cc.EvalRotate(c1, -2)
	checkErr(err, "EvalRotate -2")
	defer cRot2.Close()

	// Homomorphic conjugation
	keyTag, err := c1.GetKeyTag()
	checkErr(err, "GetKeyTag")

	evalConjKeyMap := cc.GetEvalAutomorphismKeyMap(keyTag)
	if evalConjKeyMap == nil {
		log.Fatal("GetEvalAutomorphismKeyMap returned nil")
	}

	cConj1, err := cc.EvalAutomorphism(c1, indexConj, evalConjKeyMap)
	checkErr(err, "EvalAutomorphism")
	defer cConj1.Close()

	// Multiplication by a complex constant
	cMulC, err := cc.EvalMultComplex(c1, constComplex)
	checkErr(err, "EvalMult complex constant")
	defer cMulC.Close()

	// Additions by complex constants
	cAddC, err := cc.EvalAddComplex(c2, constComplex)
	checkErr(err, "EvalAdd complex constant")
	defer cAddC.Close()

	checkErr(cc.EvalAddInPlaceComplex(cAddC, constComplex2), "EvalAddInPlace complex constant")

	// Subtractions by complex constants
	cSubC, err := cc.EvalSubComplex(c2, constComplex)
	checkErr(err, "EvalSub complex constant")
	defer cSubC.Close()

	checkErr(cc.EvalSubInPlaceComplex(cSubC, constComplex2), "EvalSubInPlace complex constant")

	// Step 5: Decryption and output
	fmt.Println("\nDecrypted complex inputs:")

	result, err := cc.Decrypt(keys, c1)
	checkErr(err, "Decrypt c1")
	defer result.Close()
	val1, err := result.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue c1")
	printComplexVector("x1 = ", val1, batchSize)

	result2, err := cc.Decrypt(keys, c2)
	checkErr(err, "Decrypt c2")
	defer result2.Close()
	val2, err := result2.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue c2")
	printComplexVector("x2 = ", val2, batchSize)

	fmt.Println("\nResults of homomorphic computations:")

	// Decrypt addition result
	resultAdd, err := cc.Decrypt(keys, cAdd)
	checkErr(err, "Decrypt cAdd")
	defer resultAdd.Close()
	valAdd, err := resultAdd.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue cAdd")
	printComplexVector("x1 + x2 = ", valAdd, batchSize)

	// Decrypt subtraction result
	resultSub, err := cc.Decrypt(keys, cSub)
	checkErr(err, "Decrypt cSub")
	defer resultSub.Close()
	valSub, err := resultSub.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue cSub")
	printComplexVector("x1 - x2 = ", valSub, batchSize)

	// Decrypt scalar multiplication result
	resultScalar, err := cc.Decrypt(keys, cScalar)
	checkErr(err, "Decrypt cScalar")
	defer resultScalar.Close()
	valScalar, err := resultScalar.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue cScalar")
	printComplexVector("4 * x1 = ", valScalar, batchSize)

	// Decrypt multiplication result
	resultMul, err := cc.Decrypt(keys, cMul)
	checkErr(err, "Decrypt cMul")
	defer resultMul.Close()
	valMul, err := resultMul.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue cMul")
	printComplexVector("x1 * x2 = ", valMul, batchSize)

	// Decrypt rotation results
	resultRot1, err := cc.Decrypt(keys, cRot1)
	checkErr(err, "Decrypt cRot1")
	defer resultRot1.Close()
	valRot1, err := resultRot1.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue cRot1")
	fmt.Println("\nIn rotations, very small outputs (~10^-10 here) correspond to 0's:")
	printComplexVector("x1 rotated by 1 = ", valRot1, batchSize)

	resultRot2, err := cc.Decrypt(keys, cRot2)
	checkErr(err, "Decrypt cRot2")
	defer resultRot2.Close()
	valRot2, err := resultRot2.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue cRot2")
	printComplexVector("x1 rotated by -2 = ", valRot2, batchSize)

	// Decrypt conjugation result
	resultConj, err := cc.Decrypt(keys, cConj1)
	checkErr(err, "Decrypt cConj1")
	defer resultConj.Close()
	valConj, err := resultConj.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue cConj1")
	printComplexVector("x1 conjugated = ", valConj, batchSize)

	// Decrypt multiplication by complex constant result
	resultMulC, err := cc.Decrypt(keys, cMulC)
	checkErr(err, "Decrypt cMulC")
	defer resultMulC.Close()
	valMulC, err := resultMulC.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue cMulC")
	printComplexVector("x1 * (1 - 2i) = ", valMulC, batchSize)

	// Decrypt addition by complex constants result
	resultAddC, err := cc.Decrypt(keys, cAddC)
	checkErr(err, "Decrypt cAddC")
	defer resultAddC.Close()
	valAddC, err := resultAddC.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue cAddC")
	printComplexVector("x2 + (1 - 2i) + (1 + 0.5i) = ", valAddC, batchSize)

	// Decrypt subtraction by complex constants result
	resultSubC, err := cc.Decrypt(keys, cSubC)
	checkErr(err, "Decrypt cSubC")
	defer resultSubC.Close()
	valSubC, err := resultSubC.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue cSubC")
	printComplexVector("x2 - (1 - 2i) - (1 + 0.5i) = ", valSubC, batchSize)

	fmt.Println("\nExample completed successfully!")
}

func simpleBootstrappingComplex() {
	fmt.Println("\n=================Bootstrapping Complex Numbers=====================")

	parameters, err := openfhe.NewParamsCKKSRNS()
	checkErr(err, "NewParamsCKKSRNS")
	defer parameters.Close()

	// A1) Secret key distribution
	secretKeyDist := openfhe.SecretKeyUniformTernary
	checkErr(parameters.SetSecretKeyDist(secretKeyDist), "SetSecretKeyDist")

	// A2) Security level - using NotSet for faster execution
	checkErr(parameters.SetSecurityLevel(openfhe.HEStdNotSet), "SetSecurityLevel")
	checkErr(parameters.SetRingDim(1<<12), "SetRingDim")

	// A3) Scaling parameters
	nativeInt := openfhe.GetNativeInt()
	var rescaleTech int
	var dcrtBits int
	var firstMod int

	if nativeInt == 128 {
		rescaleTech = openfhe.FIXEDAUTO
		dcrtBits = 78
		firstMod = 89
	} else {
		rescaleTech = openfhe.FLEXIBLEAUTO
		dcrtBits = 59
		firstMod = 60
	}

	checkErr(parameters.SetScalingModSize(dcrtBits), "SetScalingModSize")
	checkErr(parameters.SetScalingTechnique(rescaleTech), "SetScalingTechnique")
	checkErr(parameters.SetFirstModSize(firstMod), "SetFirstModSize")

	// A4) Data type
	checkErr(parameters.SetCKKSDataType(openfhe.CKKS_DATA_TYPE_COMPLEX), "SetCKKSDataType")

	// A5) Multiplicative depth
	levelBudget := []uint32{4, 4}
	levelsAvailableAfterBootstrap := uint32(10)
	bootDepth := openfhe.GetBootstrapDepth(levelBudget, secretKeyDist)
	depth := int(levelsAvailableAfterBootstrap + bootDepth)
	checkErr(parameters.SetMultiplicativeDepth(depth), "SetMultiplicativeDepth")

	cryptoContext, err := openfhe.NewCryptoContextCKKS(parameters)
	checkErr(err, "NewCryptoContextCKKS")
	defer cryptoContext.Close()

	checkErr(cryptoContext.Enable(openfhe.PKE), "Enable PKE")
	checkErr(cryptoContext.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	checkErr(cryptoContext.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")
	checkErr(cryptoContext.Enable(openfhe.ADVANCEDSHE), "Enable ADVANCEDSHE")
	checkErr(cryptoContext.Enable(openfhe.FHE), "Enable FHE")

	ringDim := cryptoContext.GetRingDimension()
	numSlots := uint32(ringDim / 2)
	fmt.Printf("CKKS scheme is using ring dimension %d\n\n", ringDim)

	checkErr(cryptoContext.EvalBootstrapSetupSimple(levelBudget), "EvalBootstrapSetup")

	keyPair, err := cryptoContext.KeyGen()
	checkErr(err, "KeyGen")
	defer keyPair.Close()

	checkErr(cryptoContext.EvalMultKeyGen(keyPair), "EvalMultKeyGen")
	checkErr(cryptoContext.EvalBootstrapKeyGen(keyPair, numSlots), "EvalBootstrapKeyGen")

	x := []complex128{
		0.25 + 0.25i, 0.5 - 0.5i, 0.75 + 0.75i, 1.0 - 1.i,
		2.0 + 2.i, 3.0 - 3.i, 4.0 + 4.i, 5.0 - 5.i,
	}
	encodedLength := len(x)

	// We start with a depleted ciphertext that has used up all of its levels
	ptxt, err := cryptoContext.MakeCKKSComplexPackedPlaintextWithParams(x, 1, depth-1)
	checkErr(err, "MakeCKKSComplexPackedPlaintextWithParams")
	defer ptxt.Close()

	printComplexVector("Input", x, encodedLength)

	ciph, err := cryptoContext.Encrypt(keyPair, ptxt)
	checkErr(err, "Encrypt")
	defer ciph.Close()

	level, ok := ciph.GetLevel()
	if !ok {
		log.Fatal("GetLevel failed")
	}
	fmt.Printf("Initial number of levels remaining: %d\n", depth-level)

	// Perform the bootstrapping operation
	ciphertextAfter, err := cryptoContext.EvalBootstrap(ciph)
	checkErr(err, "EvalBootstrap")
	defer ciphertextAfter.Close()

	levelAfter, ok := ciphertextAfter.GetLevel()
	if !ok {
		log.Fatal("GetLevel failed after bootstrap")
	}
	noiseScaleDeg := ciphertextAfter.GetNoiseScaleDeg()
	levelsRemaining := depth - levelAfter - int(noiseScaleDeg-1)
	fmt.Printf("Number of levels remaining after bootstrapping: %d\n\n", levelsRemaining)

	result, err := cryptoContext.Decrypt(keyPair, ciphertextAfter)
	checkErr(err, "Decrypt")
	defer result.Close()

	resultVec, err := result.GetComplexPackedValue()
	checkErr(err, "GetComplexPackedValue")

	fmt.Println("Output after bootstrapping:")
	printComplexVector("\t", resultVec, encodedLength)
}
