package main

import (
	"fmt"
	// Import your new package. Adjust path to match your go.mod
	"github.com/dozyio/openfhe-go/openfhe"
)

// Helper for printing
func truncateFloatVector(vec []float64, maxLen int) []float64 {
	if len(vec) > maxLen {
		return vec[:maxLen]
	}
	return vec
}

func main() {
	fmt.Println("--- Go simple-real-numbers example starting ---")

	// 1. Set up parameters
	scalingModSize := 50
	batchSize := 8
	multDepth := 1

	parameters := openfhe.NewParamsCKKSRNS() // Use package
	parameters.SetMultiplicativeDepth(multDepth)
	parameters.SetScalingModSize(scalingModSize)
	parameters.SetBatchSize(batchSize)
	fmt.Println("Parameters set.")

	// 2. Generate CryptoContext
	cc := openfhe.NewCryptoContextCKKS(parameters) // Use package
	cc.Enable(openfhe.PKE)
	cc.Enable(openfhe.KEYSWITCH)
	cc.Enable(openfhe.LEVELEDSHE)
	fmt.Println("CryptoContext generated.")

	// 3. Key Generation
	keys := cc.KeyGen()
	cc.EvalMultKeyGen(keys)
	fmt.Println("Keys generated.")

	// 4. Encoding and Encryption
	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	ciphertext := cc.Encrypt(keys, plaintext)
	fmt.Printf("Plaintext: %v\n", truncateFloatVector(vectorOfDoubles, batchSize))
	fmt.Println("Encryption complete.")

	// 5. Homomorphic Operations
	ciphertext_add := cc.EvalAdd(ciphertext, ciphertext)
	ciphertext_sub := cc.EvalSub(ciphertext, ciphertext)
	ciphertext_mul := cc.EvalMult(ciphertext, ciphertext)
	ciphertext_mul_rescaled := cc.Rescale(ciphertext_mul)
	fmt.Println("Homomorphic operations complete.")

	// 6. Decryption
	plaintext_dec_add := cc.Decrypt(keys, ciphertext_add)
	plaintext_dec_sub := cc.Decrypt(keys, ciphertext_sub)
	plaintext_dec_mul := cc.Decrypt(keys, ciphertext_mul_rescaled)
	fmt.Println("Decryption complete.")

	// 7. Print results
	fmt.Println("\n--- Results (CKKS is approximate) ---")
	fmt.Printf("Original vector:      %.6f...\n", truncateFloatVector(plaintext_dec_add.GetRealPackedValue(), batchSize))
	fmt.Printf("Decrypted Add (v+v):  %.6f...\n", truncateFloatVector(plaintext_dec_add.GetRealPackedValue(), batchSize))
	fmt.Printf("Decrypted Sub (v-v):  %.6f...\n", truncateFloatVector(plaintext_dec_sub.GetRealPackedValue(), batchSize))
	fmt.Printf("Decrypted Mult (v*v): %.6f...\n", truncateFloatVector(plaintext_dec_mul.GetRealPackedValue(), batchSize))
}
