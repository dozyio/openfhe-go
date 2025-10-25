package main

import (
	"fmt"
	// Import the 'openfhe' package
	"github.com/dozyio/openfhe-go/openfhe"
)

// Helper function to truncate vectors for printing
func truncateVector(vec []int64, maxLen int) []int64 {
	if len(vec) > maxLen {
		return vec[:maxLen]
	}
	return vec
}

func main() {
	fmt.Println("--- Go simple-integers-bgvrns example starting ---")

	// 1. Set CryptoContext Parameters
	parameters := openfhe.NewParamsBGVrns() // Use BGV Params
	parameters.SetPlaintextModulus(65537)
	parameters.SetMultiplicativeDepth(2)
	fmt.Println("Parameters set.")

	// 2. Generate CryptoContext
	cc := openfhe.NewCryptoContextBGV(parameters) // Use BGV Context constructor

	// Enable features
	cc.Enable(openfhe.PKE)
	cc.Enable(openfhe.KEYSWITCH)
	cc.Enable(openfhe.LEVELEDSHE)
	fmt.Println("CryptoContext generated.")

	// 3. Key Generation
	keyPair := cc.KeyGen()
	cc.EvalMultKeyGen(keyPair)
	// Rotation keys for indices 1, 2, -1, -2
	cc.EvalRotateKeyGen(keyPair, []int32{1, 2, -1, -2})
	fmt.Println("Keys generated.")

	// 4. Encoding and Encryption
	vectorOfInts1 := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext1 := cc.MakePackedPlaintext(vectorOfInts1) // Re-use MakePackedPlaintext

	vectorOfInts2 := []int64{3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext2 := cc.MakePackedPlaintext(vectorOfInts2)

	vectorOfInts3 := []int64{1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext3 := cc.MakePackedPlaintext(vectorOfInts3)

	ciphertext1 := cc.Encrypt(keyPair, plaintext1)
	ciphertext2 := cc.Encrypt(keyPair, plaintext2)
	ciphertext3 := cc.Encrypt(keyPair, plaintext3)
	fmt.Printf("Plaintext #1: %v\n", truncateVector(vectorOfInts1, 12))
	fmt.Printf("Plaintext #2: %v\n", truncateVector(vectorOfInts2, 12))
	fmt.Printf("Plaintext #3: %v\n", truncateVector(vectorOfInts3, 12))
	fmt.Println("Encryption complete.")

	// 5. Evaluation
	// Homomorphic additions
	ciphertextAdd12 := cc.EvalAdd(ciphertext1, ciphertext2)
	ciphertextAddResult := cc.EvalAdd(ciphertextAdd12, ciphertext3)

	// Homomorphic multiplications
	ciphertextMult12 := cc.EvalMult(ciphertext1, ciphertext2)
	ciphertextMultResult := cc.EvalMult(ciphertextMult12, ciphertext3)

	// Homomorphic rotations
	ciphertextRot1 := cc.EvalRotate(ciphertext1, 1)
	ciphertextRot2 := cc.EvalRotate(ciphertext1, 2)
	ciphertextRotNeg1 := cc.EvalRotate(ciphertext1, -1)
	ciphertextRotNeg2 := cc.EvalRotate(ciphertext1, -2)
	fmt.Println("Homomorphic operations complete.")

	// 6. Decryption
	plaintextAddResult := cc.Decrypt(keyPair, ciphertextAddResult)
	plaintextMultResult := cc.Decrypt(keyPair, ciphertextMultResult)
	plaintextRot1 := cc.Decrypt(keyPair, ciphertextRot1)
	plaintextRot2 := cc.Decrypt(keyPair, ciphertextRot2)
	plaintextRotNeg1 := cc.Decrypt(keyPair, ciphertextRotNeg1)
	plaintextRotNeg2 := cc.Decrypt(keyPair, ciphertextRotNeg2)
	fmt.Println("Decryption complete.")

	// Set length for rotated plaintexts (optional but good practice for BGV)
	plaintextRot1.SetLength(len(vectorOfInts1))
	plaintextRot2.SetLength(len(vectorOfInts1))
	plaintextRotNeg1.SetLength(len(vectorOfInts1))
	plaintextRotNeg2.SetLength(len(vectorOfInts1))

	// 7. Print results
	fmt.Println("\n--- Results of homomorphic computations ---")
	fmt.Printf("#1 + #2 + #3 = %v\n", truncateVector(plaintextAddResult.GetPackedValue(), 12))
	fmt.Printf("#1 * #2 * #3 = %v\n", truncateVector(plaintextMultResult.GetPackedValue(), 12))
	fmt.Printf("Left rotation of #1 by 1 = %v\n", truncateVector(plaintextRot1.GetPackedValue(), 12))
	fmt.Printf("Left rotation of #1 by 2 = %v\n", truncateVector(plaintextRot2.GetPackedValue(), 12))
	fmt.Printf("Right rotation of #1 by 1 = %v\n", truncateVector(plaintextRotNeg1.GetPackedValue(), 12))
	fmt.Printf("Right rotation of #1 by 2 = %v\n", truncateVector(plaintextRotNeg2.GetPackedValue(), 12))
}
