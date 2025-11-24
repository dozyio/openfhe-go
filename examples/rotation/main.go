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

func main() {
	fmt.Println("\nThis code shows how the EvalRotate and EvalMerge operations work for different schemes (BFV and CKKS).\n")

	fmt.Println("\n========== BFVrns.EvalRotate - Power-of-Two Cyclotomics ===========")
	BFVrnsEvalRotate2n()

	fmt.Println("\n========== CKKS.EvalRotate - Power-of-Two Cyclotomics ===========")
	CKKSEvalRotate2n()

	fmt.Println("\n========== BFVrns.EvalMerge - Power-of-Two Cyclotomics ===========")
	BFVrnsEvalMerge2n()
}

func BFVrnsEvalRotate2n() {
	// Setup parameters
	parameters, err := openfhe.NewParamsBFVrns()
	checkErr(err, "NewParamsBFVrns")
	defer parameters.Close()

	checkErr(parameters.SetPlaintextModulus(65537), "SetPlaintextModulus")
	checkErr(parameters.SetMaxRelinSkDeg(3), "SetMaxRelinSkDeg")

	// Generate crypto context
	cc, err := openfhe.NewCryptoContextBFV(parameters)
	checkErr(err, "NewCryptoContextBFV")
	defer cc.Close()

	// Enable features
	checkErr(cc.Enable(openfhe.PKE), "Enable PKE")
	checkErr(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	checkErr(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")

	// Get ring dimension
	ringDim := cc.GetRingDimension()
	n := int32(ringDim / 2)

	// Key generation
	keys, err := cc.KeyGen()
	checkErr(err, "KeyGen")
	defer keys.Close()

	// Generate rotation keys for various indices
	indexList := []int32{2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5}
	checkErr(cc.EvalRotateKeyGen(keys, indexList), "EvalRotateKeyGen")

	// Create plaintext vector
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	// Resize to n and set last few elements
	for len(vectorOfInts) < int(n) {
		vectorOfInts = append(vectorOfInts, 0)
	}
	vectorOfInts[n-1] = int64(n)
	vectorOfInts[n-2] = int64(n - 1)
	vectorOfInts[n-3] = int64(n - 2)

	// Encode and encrypt
	intArray, err := cc.MakePackedPlaintext(vectorOfInts)
	checkErr(err, "MakePackedPlaintext")
	defer intArray.Close()

	ciphertext, err := cc.Encrypt(keys, intArray)
	checkErr(err, "Encrypt")
	defer ciphertext.Close()

	// Perform rotations
	for _, idx := range indexList {
		permutedCiphertext, err := cc.EvalRotate(ciphertext, idx)
		checkErr(err, "EvalRotate")
		defer permutedCiphertext.Close()

		// Decrypt
		intArrayNew, err := cc.Decrypt(keys, permutedCiphertext)
		checkErr(err, "Decrypt")
		defer intArrayNew.Close()

		// Get and print result (showing first 10 elements)
		result, err := intArrayNew.GetPackedValue()
		checkErr(err, "GetPackedValue")

		// Truncate to first 10 elements for display
		displayResult := result
		if len(result) > 10 {
			displayResult = result[:10]
		}

		fmt.Printf("Automorphed array - at index %d: %v\n", idx, displayResult)
	}
}

func CKKSEvalRotate2n() {
	// Setup parameters
	parameters, err := openfhe.NewParamsCKKSRNS()
	checkErr(err, "NewParamsCKKSRNS")
	defer parameters.Close()

	checkErr(parameters.SetMultiplicativeDepth(2), "SetMultiplicativeDepth")
	checkErr(parameters.SetScalingModSize(40), "SetScalingModSize")

	// Generate crypto context
	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	checkErr(err, "NewCryptoContextCKKS")
	defer cc.Close()

	// Enable features
	checkErr(cc.Enable(openfhe.PKE), "Enable PKE")
	checkErr(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	checkErr(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")

	// Get ring dimension and calculate n
	// For CKKS, cyclotomicOrder = 2 * ringDim, so n = cyclotomicOrder / 4 = ringDim / 2
	ringDim := cc.GetRingDimension()
	n := int32(ringDim / 2)

	// Key generation
	keys, err := cc.KeyGen()
	checkErr(err, "KeyGen")
	defer keys.Close()

	// Generate rotation keys for various indices
	indexList := []int32{2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5}
	checkErr(cc.EvalRotateKeyGen(keys, indexList), "EvalRotateKeyGen")

	// Create plaintext vector
	vectorOfDoubles := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	// Resize to n and set last few elements
	for len(vectorOfDoubles) < int(n) {
		vectorOfDoubles = append(vectorOfDoubles, 0)
	}
	vectorOfDoubles[n-1] = float64(n)
	vectorOfDoubles[n-2] = float64(n - 1)
	vectorOfDoubles[n-3] = float64(n - 2)

	// Encode and encrypt
	intArray, err := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	checkErr(err, "MakeCKKSPackedPlaintext")
	defer intArray.Close()

	ciphertext, err := cc.Encrypt(keys, intArray)
	checkErr(err, "Encrypt")
	defer ciphertext.Close()

	// Perform rotations
	for _, idx := range indexList {
		permutedCiphertext, err := cc.EvalRotate(ciphertext, idx)
		checkErr(err, "EvalRotate")
		defer permutedCiphertext.Close()

		// Decrypt
		intArrayNew, err := cc.Decrypt(keys, permutedCiphertext)
		checkErr(err, "Decrypt")
		defer intArrayNew.Close()

		// Get and print result (showing first 10 elements)
		result, err := intArrayNew.GetRealPackedValue()
		checkErr(err, "GetRealPackedValue")

		// Truncate to first 10 elements for display
		displayResult := result
		if len(result) > 10 {
			displayResult = result[:10]
		}

		fmt.Printf("Automorphed array - at index %d: %v\n", idx, displayResult)
	}
}

func BFVrnsEvalMerge2n() {
	// Setup parameters
	parameters, err := openfhe.NewParamsBFVrns()
	checkErr(err, "NewParamsBFVrns")
	defer parameters.Close()

	checkErr(parameters.SetPlaintextModulus(65537), "SetPlaintextModulus")
	checkErr(parameters.SetMultiplicativeDepth(2), "SetMultiplicativeDepth")
	checkErr(parameters.SetMaxRelinSkDeg(3), "SetMaxRelinSkDeg")

	// Generate crypto context
	cc, err := openfhe.NewCryptoContextBFV(parameters)
	checkErr(err, "NewCryptoContextBFV")
	defer cc.Close()

	// Enable features (ADVANCEDSHE is required for EvalMerge)
	checkErr(cc.Enable(openfhe.PKE), "Enable PKE")
	checkErr(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	checkErr(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")
	checkErr(cc.Enable(openfhe.ADVANCEDSHE), "Enable ADVANCEDSHE")

	// Key generation
	keys, err := cc.KeyGen()
	checkErr(err, "KeyGen")
	defer keys.Close()

	// Generate rotation keys for merging (need negative indices)
	indexList := []int32{-1, -2, -3, -4, -5}
	checkErr(cc.EvalRotateKeyGen(keys, indexList), "EvalRotateKeyGen")

	// Create and encrypt multiple ciphertexts
	var ciphertexts []*openfhe.Ciphertext

	vectorOfInts1 := []int64{32, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	intArray1, err := cc.MakePackedPlaintext(vectorOfInts1)
	checkErr(err, "MakePackedPlaintext 1")
	defer intArray1.Close()
	ct1, err := cc.Encrypt(keys, intArray1)
	checkErr(err, "Encrypt 1")
	defer ct1.Close()
	ciphertexts = append(ciphertexts, ct1)

	vectorOfInts2 := []int64{2, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	intArray2, err := cc.MakePackedPlaintext(vectorOfInts2)
	checkErr(err, "MakePackedPlaintext 2")
	defer intArray2.Close()
	ct2, err := cc.Encrypt(keys, intArray2)
	checkErr(err, "Encrypt 2")
	defer ct2.Close()
	ciphertexts = append(ciphertexts, ct2)

	vectorOfInts3 := []int64{4, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	intArray3, err := cc.MakePackedPlaintext(vectorOfInts3)
	checkErr(err, "MakePackedPlaintext 3")
	defer intArray3.Close()
	ct3, err := cc.Encrypt(keys, intArray3)
	checkErr(err, "Encrypt 3")
	defer ct3.Close()
	ciphertexts = append(ciphertexts, ct3)

	vectorOfInts4 := []int64{8, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	intArray4, err := cc.MakePackedPlaintext(vectorOfInts4)
	checkErr(err, "MakePackedPlaintext 4")
	defer intArray4.Close()
	ct4, err := cc.Encrypt(keys, intArray4)
	checkErr(err, "Encrypt 4")
	defer ct4.Close()
	ciphertexts = append(ciphertexts, ct4)

	vectorOfInts5 := []int64{16, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	intArray5, err := cc.MakePackedPlaintext(vectorOfInts5)
	checkErr(err, "MakePackedPlaintext 5")
	defer intArray5.Close()
	ct5, err := cc.Encrypt(keys, intArray5)
	checkErr(err, "Encrypt 5")
	defer ct5.Close()
	ciphertexts = append(ciphertexts, ct5)

	// Print input ciphertexts
	result1, _ := intArray1.GetPackedValue()
	result2, _ := intArray2.GetPackedValue()
	result3, _ := intArray3.GetPackedValue()
	result4, _ := intArray4.GetPackedValue()
	result5, _ := intArray5.GetPackedValue()
	fmt.Printf("Input ciphertext %v\n", result1[:10])
	fmt.Printf("Input ciphertext %v\n", result2[:10])
	fmt.Printf("Input ciphertext %v\n", result3[:10])
	fmt.Printf("Input ciphertext %v\n", result4[:10])
	fmt.Printf("Input ciphertext %v\n", result5[:10])

	// Merge ciphertexts
	mergedCiphertext, err := cc.EvalMerge(ciphertexts)
	checkErr(err, "EvalMerge")
	defer mergedCiphertext.Close()

	// Decrypt merged result
	intArrayNew, err := cc.Decrypt(keys, mergedCiphertext)
	checkErr(err, "Decrypt")
	defer intArrayNew.Close()

	// Get and print result
	result, err := intArrayNew.GetPackedValue()
	checkErr(err, "GetPackedValue")

	displayResult := result
	if len(result) > 10 {
		displayResult = result[:10]
	}

	fmt.Printf("\nMerged ciphertext %v\n", displayResult)
}
