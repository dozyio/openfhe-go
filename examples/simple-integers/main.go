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

// This helper function truncates the vector for printing
func truncateVector(vec []int64, maxLen int) []int64 {
	if len(vec) > maxLen {
		return vec[:maxLen]
	}
	return vec
}

// --- main() ---
func main() {
	fmt.Println("--- Go simple-integers example starting ---")

	// 1. Set up parameters
	// Use the functions from the 'openfhe' package
	parameters, err := openfhe.NewParamsBFVrns()
	checkErr(err, "NewParamsBFVrns")
	defer parameters.Close()

	checkErr(parameters.SetPlaintextModulus(65537), "SetPlaintextModulus")
	checkErr(parameters.SetMultiplicativeDepth(2), "SetMultiplicativeDepth")
	fmt.Println("Parameters set.")

	// 2. Generate CryptoContext
	// We call the BFV-specific constructor
	cc, err := openfhe.NewCryptoContextBFV(parameters)
	checkErr(err, "NewCryptoContextBFV")
	defer cc.Close()

	// Use the constants from the 'openfhe' package
	checkErr(cc.Enable(openfhe.PKE), "Enable PKE")
	checkErr(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	checkErr(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")
	fmt.Println("CryptoContext generated.")

	// 3. Key Generation
	keys, err := cc.KeyGen()
	checkErr(err, "KeyGen")
	defer keys.Close()

	checkErr(cc.EvalMultKeyGen(keys), "EvalMultKeyGen")
	// Use an int32 slice
	checkErr(cc.EvalRotateKeyGen(keys, []int32{1, -2}), "EvalRotateKeyGen")
	fmt.Println("Keys generated.")

	// 4. Encoding and Encryption
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext, err := cc.MakePackedPlaintext(vectorOfInts)
	checkErr(err, "MakePackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	checkErr(err, "Encrypt")
	defer ciphertext.Close()

	fmt.Printf("Plaintext: %v\n", truncateVector(vectorOfInts, 12))
	fmt.Println("Encryption complete.")

	// 5. Homomorphic Operations
	ciphertext_add, err := cc.EvalAdd(ciphertext, ciphertext)
	checkErr(err, "EvalAdd")
	defer ciphertext_add.Close()

	ciphertext_mul, err := cc.EvalMult(ciphertext, ciphertext)
	checkErr(err, "EvalMult")
	defer ciphertext_mul.Close()

	// Use int32 for index
	ciphertext_rot1, err := cc.EvalRotate(ciphertext, 1)
	checkErr(err, "EvalRotate 1")
	defer ciphertext_rot1.Close()

	ciphertext_rot2, err := cc.EvalRotate(ciphertext, -2)
	checkErr(err, "EvalRotate -2")
	defer ciphertext_rot2.Close()

	fmt.Println("Homomorphic operations complete.")

	// 6. Decryption
	plaintext_dec_add, err := cc.Decrypt(keys, ciphertext_add)
	checkErr(err, "Decrypt Add")
	defer plaintext_dec_add.Close()

	plaintext_dec_mul, err := cc.Decrypt(keys, ciphertext_mul)
	checkErr(err, "Decrypt Mult")
	defer plaintext_dec_mul.Close()

	plaintext_dec_rot1, err := cc.Decrypt(keys, ciphertext_rot1)
	checkErr(err, "Decrypt Rot1")
	defer plaintext_dec_rot1.Close()

	plaintext_dec_rot2, err := cc.Decrypt(keys, ciphertext_rot2)
	checkErr(err, "Decrypt Rot2")
	defer plaintext_dec_rot2.Close()

	fmt.Println("Decryption complete.")

	// 7. Print results
	valAdd, err := plaintext_dec_add.GetPackedValue()
	checkErr(err, "GetPackedValue Add")
	valMul, err := plaintext_dec_mul.GetPackedValue()
	checkErr(err, "GetPackedValue Mult")
	valRot1, err := plaintext_dec_rot1.GetPackedValue()
	checkErr(err, "GetPackedValue Rot1")
	valRot2, err := plaintext_dec_rot2.GetPackedValue()
	checkErr(err, "GetPackedValue Rot2")

	fmt.Println("\n--- Results ---")
	fmt.Printf("Original vector:        %v\n", truncateVector(vectorOfInts, 12))
	fmt.Printf("Decrypted Add (v+v):    %v\n", truncateVector(valAdd, 12))
	fmt.Printf("Decrypted Mult (v*v):   %v\n", truncateVector(valMul, 12))
	fmt.Printf("Decrypted Rotate(v, 1): %v\n", truncateVector(valRot1, 12))
	fmt.Printf("Decrypted Rotate(v,-2): %v\n", truncateVector(valRot2, 12))
}
