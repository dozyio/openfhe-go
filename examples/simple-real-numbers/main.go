package main

import (
	"fmt"
	"log" // NEW

	// Import your new package. Adjust path to match your go.mod
	"github.com/dozyio/openfhe-go/openfhe"
)

// NEW: Helper for error checking
func checkErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

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

	parameters, err := openfhe.NewParamsCKKSRNS() // Use package
	checkErr(err, "NewParamsCKKSRNS")
	defer parameters.Close()

	checkErr(parameters.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")
	checkErr(parameters.SetScalingModSize(scalingModSize), "SetScalingModSize")
	checkErr(parameters.SetBatchSize(batchSize), "SetBatchSize")
	fmt.Println("Parameters set.")

	// 2. Generate CryptoContext
	cc, err := openfhe.NewCryptoContextCKKS(parameters) // Use package
	checkErr(err, "NewCryptoContextCKKS")
	defer cc.Close()

	checkErr(cc.Enable(openfhe.PKE), "Enable PKE")
	checkErr(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	checkErr(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")
	fmt.Println("CryptoContext generated.")

	// 3. Key Generation
	keys, err := cc.KeyGen()
	checkErr(err, "KeyGen")
	defer keys.Close()

	checkErr(cc.EvalMultKeyGen(keys), "EvalMultKeyGen")
	fmt.Println("Keys generated.")

	// 4. Encoding and Encryption
	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext, err := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	checkErr(err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	checkErr(err, "Encrypt")
	defer ciphertext.Close()

	fmt.Printf("Plaintext: %v\n", truncateFloatVector(vectorOfDoubles, batchSize))
	fmt.Println("Encryption complete.")

	// 5. Homomorphic Operations
	ciphertext_add, err := cc.EvalAdd(ciphertext, ciphertext)
	checkErr(err, "EvalAdd")
	defer ciphertext_add.Close()

	ciphertext_sub, err := cc.EvalSub(ciphertext, ciphertext)
	checkErr(err, "EvalSub")
	defer ciphertext_sub.Close()

	ciphertext_mul, err := cc.EvalMult(ciphertext, ciphertext)
	checkErr(err, "EvalMult")
	defer ciphertext_mul.Close()

	ciphertext_mul_rescaled, err := cc.Rescale(ciphertext_mul)
	checkErr(err, "Rescale")
	defer ciphertext_mul_rescaled.Close()
	fmt.Println("Homomorphic operations complete.")

	// 6. Decryption
	plaintext_dec_add, err := cc.Decrypt(keys, ciphertext_add)
	checkErr(err, "Decrypt Add")
	defer plaintext_dec_add.Close()
	plaintext_dec_sub, err := cc.Decrypt(keys, ciphertext_sub)
	checkErr(err, "Decrypt Sub")
	defer plaintext_dec_sub.Close()
	plaintext_dec_mul, err := cc.Decrypt(keys, ciphertext_mul_rescaled)
	checkErr(err, "Decrypt Mult")
	defer plaintext_dec_mul.Close()
	fmt.Println("Decryption complete.")

	// 7. Print results
	valAdd, err := plaintext_dec_add.GetRealPackedValue()
	checkErr(err, "GetRealPackedValue Add")
	valSub, err := plaintext_dec_sub.GetRealPackedValue()
	checkErr(err, "GetRealPackedValue Sub")
	valMul, err := plaintext_dec_mul.GetRealPackedValue()
	checkErr(err, "GetRealPackedValue Mult")

	fmt.Println("\n--- Results (CKKS is approximate) ---")
	// Note: Printing original vector from the *first* decrypted result
	fmt.Printf("Original vector:    %.6f...\n", truncateFloatVector(valAdd, batchSize))
	fmt.Printf("Decrypted Add (v+v):  %.6f...\n", truncateFloatVector(valAdd, batchSize))
	fmt.Printf("Decrypted Sub (v-v):  %.6f...\n", truncateFloatVector(valSub, batchSize))
	fmt.Printf("Decrypted Mult (v*v): %.6f...\n", truncateFloatVector(valMul, batchSize))
}
