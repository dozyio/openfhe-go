package main

import (
	"fmt"
	"log" // NEW: for error handling

	// Import the 'openfhe' package
	"github.com/dozyio/openfhe-go/openfhe"
)

// NEW: Helper for error checking
func checkErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

// Helper function to truncate vectors for printing
func truncateVector(vec []int64, maxLen int) []int64 {
	// ... (function unchanged) ...
	if len(vec) > maxLen {
		return vec[:maxLen]
	}
	return vec
}

func main() {
	fmt.Println("--- Go simple-integers-bgvrns example starting ---")

	// 1. Set CryptoContext Parameters
	parameters, err := openfhe.NewParamsBGVrns() // Use BGV Params
	checkErr(err, "NewParamsBGVrns")
	defer parameters.Close()

	checkErr(parameters.SetPlaintextModulus(65537), "SetPlaintextModulus")
	checkErr(parameters.SetMultiplicativeDepth(2), "SetMultiplicativeDepth")
	fmt.Println("Parameters set.")

	// 2. Generate CryptoContext
	cc, err := openfhe.NewCryptoContextBGV(parameters) // Use BGV Context constructor
	checkErr(err, "NewCryptoContextBGV")
	defer cc.Close()

	// Enable features
	checkErr(cc.Enable(openfhe.PKE), "Enable PKE")
	checkErr(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	checkErr(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")
	fmt.Println("CryptoContext generated.")

	// 3. Key Generation
	keyPair, err := cc.KeyGen()
	checkErr(err, "KeyGen")
	defer keyPair.Close()

	checkErr(cc.EvalMultKeyGen(keyPair), "EvalMultKeyGen")
	// Rotation keys for indices 1, 2, -1, -2
	checkErr(cc.EvalRotateKeyGen(keyPair, []int32{1, 2, -1, -2}), "EvalRotateKeyGen")
	fmt.Println("Keys generated.")

	// 4. Encoding and Encryption
	vectorOfInts1 := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext1, err := cc.MakePackedPlaintext(vectorOfInts1)
	checkErr(err, "MakePackedPlaintext 1")
	defer plaintext1.Close()

	vectorOfInts2 := []int64{3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext2, err := cc.MakePackedPlaintext(vectorOfInts2)
	checkErr(err, "MakePackedPlaintext 2")
	defer plaintext2.Close()

	vectorOfInts3 := []int64{1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext3, err := cc.MakePackedPlaintext(vectorOfInts3)
	checkErr(err, "MakePackedPlaintext 3")
	defer plaintext3.Close()

	ciphertext1, err := cc.Encrypt(keyPair, plaintext1)
	checkErr(err, "Encrypt 1")
	defer ciphertext1.Close()
	ciphertext2, err := cc.Encrypt(keyPair, plaintext2)
	checkErr(err, "Encrypt 2")
	defer ciphertext2.Close()
	ciphertext3, err := cc.Encrypt(keyPair, plaintext3)
	checkErr(err, "Encrypt 3")
	defer ciphertext3.Close()

	fmt.Printf("Plaintext #1: %v\n", truncateVector(vectorOfInts1, 12))
	fmt.Printf("Plaintext #2: %v\n", truncateVector(vectorOfInts2, 12))
	fmt.Printf("Plaintext #3: %v\n", truncateVector(vectorOfInts3, 12))
	fmt.Println("Encryption complete.")

	// 5. Evaluation
	// Homomorphic additions
	ciphertextAdd12, err := cc.EvalAdd(ciphertext1, ciphertext2)
	checkErr(err, "EvalAdd 1+2")
	defer ciphertextAdd12.Close()
	ciphertextAddResult, err := cc.EvalAdd(ciphertextAdd12, ciphertext3)
	checkErr(err, "EvalAdd (1+2)+3")
	defer ciphertextAddResult.Close()

	// Homomorphic multiplications
	ciphertextMult12, err := cc.EvalMult(ciphertext1, ciphertext2)
	checkErr(err, "EvalMult 1*2")
	defer ciphertextMult12.Close()
	ciphertextMultResult, err := cc.EvalMult(ciphertextMult12, ciphertext3)
	checkErr(err, "EvalMult (1*2)*3")
	defer ciphertextMultResult.Close()

	// Homomorphic rotations
	ciphertextRot1, err := cc.EvalRotate(ciphertext1, 1)
	checkErr(err, "EvalRotate 1")
	defer ciphertextRot1.Close()
	ciphertextRot2, err := cc.EvalRotate(ciphertext1, 2)
	checkErr(err, "EvalRotate 2")
	defer ciphertextRot2.Close()
	ciphertextRotNeg1, err := cc.EvalRotate(ciphertext1, -1)
	checkErr(err, "EvalRotate -1")
	defer ciphertextRotNeg1.Close()
	ciphertextRotNeg2, err := cc.EvalRotate(ciphertext1, -2)
	checkErr(err, "EvalRotate -2")
	defer ciphertextRotNeg2.Close()
	fmt.Println("Homomorphic operations complete.")

	// 6. Decryption
	plaintextAddResult, err := cc.Decrypt(keyPair, ciphertextAddResult)
	checkErr(err, "Decrypt Add")
	defer plaintextAddResult.Close()
	plaintextMultResult, err := cc.Decrypt(keyPair, ciphertextMultResult)
	checkErr(err, "Decrypt Mult")
	defer plaintextMultResult.Close()
	plaintextRot1, err := cc.Decrypt(keyPair, ciphertextRot1)
	checkErr(err, "Decrypt Rot1")
	defer plaintextRot1.Close()
	plaintextRot2, err := cc.Decrypt(keyPair, ciphertextRot2)
	checkErr(err, "Decrypt Rot2")
	defer plaintextRot2.Close()
	plaintextRotNeg1, err := cc.Decrypt(keyPair, ciphertextRotNeg1)
	checkErr(err, "Decrypt Rot-1")
	defer plaintextRotNeg1.Close()
	plaintextRotNeg2, err := cc.Decrypt(keyPair, ciphertextRotNeg2)
	checkErr(err, "Decrypt Rot-2")
	defer plaintextRotNeg2.Close()
	fmt.Println("Decryption complete.")

	// Set length for rotated plaintexts (optional but good practice for BGV)
	checkErr(plaintextRot1.SetLength(len(vectorOfInts1)), "SetLength Rot1")
	checkErr(plaintextRot2.SetLength(len(vectorOfInts1)), "SetLength Rot2")
	checkErr(plaintextRotNeg1.SetLength(len(vectorOfInts1)), "SetLength Rot-1")
	checkErr(plaintextRotNeg2.SetLength(len(vectorOfInts1)), "SetLength Rot-2")

	// 7. Print results
	valAdd, err := plaintextAddResult.GetPackedValue()
	checkErr(err, "GetPackedValue Add")
	valMult, err := plaintextMultResult.GetPackedValue()
	checkErr(err, "GetPackedValue Mult")
	valRot1, err := plaintextRot1.GetPackedValue()
	checkErr(err, "GetPackedValue Rot1")
	valRot2, err := plaintextRot2.GetPackedValue()
	checkErr(err, "GetPackedValue Rot2")
	valRotNeg1, err := plaintextRotNeg1.GetPackedValue()
	checkErr(err, "GetPackedValue Rot-1")
	valRotNeg2, err := plaintextRotNeg2.GetPackedValue()
	checkErr(err, "GetPackedValue Rot-2")

	fmt.Println("\n--- Results of homomorphic computations ---")
	fmt.Printf("#1 + #2 + #3 = %v\n", truncateVector(valAdd, 12))
	fmt.Printf("#1 * #2 * #3 = %v\n", truncateVector(valMult, 12))
	fmt.Printf("Left rotation of #1 by 1 = %v\n", truncateVector(valRot1, 12))
	fmt.Printf("Left rotation of #1 by 2 = %v\n", truncateVector(valRot2, 12))
	fmt.Printf("Right rotation of #1 by 1 = %v\n", truncateVector(valRotNeg1, 12))
	fmt.Printf("Right rotation of #1 by 2 = %v\n", truncateVector(valRotNeg2, 12))
}
