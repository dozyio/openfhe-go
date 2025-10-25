package main

import (
	"fmt"
	// Import the 'openfhe' package we just built
	"github.com/dozyio/openfhe-go/openfhe"
)

// This helper function truncates the vector for printing
func truncateVector(vec []int64, maxLen int) []int64 {
	if len(vec) > maxLen {
		return vec[:maxLen]
	}
	return vec
}

// --- main() ---
// This is the Go equivalent of the Python script,
// now using our clean 'openfhe' package.
func main() {
	fmt.Println("--- Go simple-integers example starting ---")

	// 1. Set up parameters
	// Use the functions from the 'openfhe' package
	parameters := openfhe.NewParamsBFVrns()
	parameters.SetPlaintextModulus(65537)
	parameters.SetMultiplicativeDepth(2)
	fmt.Println("Parameters set.")

	// 2. Generate CryptoContext
	// We call the BFV-specific constructor
	cc := openfhe.NewCryptoContextBFV(parameters)
	// Use the constants from the 'openfhe' package
	cc.Enable(openfhe.PKE)
	cc.Enable(openfhe.KEYSWITCH)
	cc.Enable(openfhe.LEVELEDSHE)
	fmt.Println("CryptoContext generated.")

	// 3. Key Generation
	keys := cc.KeyGen()
	cc.EvalMultKeyGen(keys)
	// Use an int32 slice
	cc.EvalRotateKeyGen(keys, []int32{1, -2})
	fmt.Println("Keys generated.")

	// 4. Encoding and Encryption
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := cc.MakePackedPlaintext(vectorOfInts)
	ciphertext := cc.Encrypt(keys, plaintext)
	fmt.Printf("Plaintext: %v\n", truncateVector(vectorOfInts, 12))
	fmt.Println("Encryption complete.")

	// 5. Homomorphic Operations
	ciphertext_add := cc.EvalAdd(ciphertext, ciphertext)
	ciphertext_mul := cc.EvalMult(ciphertext, ciphertext)
	// Use int32 for index
	ciphertext_rot1 := cc.EvalRotate(ciphertext, 1)
	ciphertext_rot2 := cc.EvalRotate(ciphertext, -2)
	fmt.Println("Homomorphic operations complete.")

	// 6. Decryption
	plaintext_dec_add := cc.Decrypt(keys, ciphertext_add)
	plaintext_dec_mul := cc.Decrypt(keys, ciphertext_mul)
	plaintext_dec_rot1 := cc.Decrypt(keys, ciphertext_rot1)
	plaintext_dec_rot2 := cc.Decrypt(keys, ciphertext_rot2)
	fmt.Println("Decryption complete.")

	// 7. Print results
	fmt.Println("\n--- Results ---")
	fmt.Printf("Original vector:        %v\n", truncateVector(vectorOfInts, 12))
	fmt.Printf("Decrypted Add (v+v):    %v\n", truncateVector(plaintext_dec_add.GetPackedValue(), 12))
	fmt.Printf("Decrypted Mult (v*v):   %v\n", truncateVector(plaintext_dec_mul.GetPackedValue(), 12))
	fmt.Printf("Decrypted Rotate(v, 1): %v\n", truncateVector(plaintext_dec_rot1.GetPackedValue(), 12))
	fmt.Printf("Decrypted Rotate(v,-2): %v\n", truncateVector(plaintext_dec_rot2.GetPackedValue(), 12))
}
