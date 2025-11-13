package main

import (
	"fmt"
	"log"

	"github.com/dozyio/openfhe-go/openfhe"
)

// This example demonstrates Proxy Re-Encryption (PRE) using BFV scheme.
// PRE allows transforming ciphertexts encrypted under one key to be encrypted
// under another key without decryption, enabling secure data sharing.
//
// Scenario: Alice encrypts her data and later wants to share it with Bob
// without decrypting it. She generates a re-encryption key that allows
// a proxy to transform her ciphertext into one that Bob can decrypt.

func main() {
	fmt.Println("PRE Buffer Example - Proxy Re-Encryption with BFV")
	fmt.Println("===================================================")

	// Setup BFV parameters
	params, err := openfhe.NewParamsBFVrns()
	if err != nil {
		log.Fatal("Failed to create BFV parameters:", err)
	}
	defer params.Close()

	// Set plaintext modulus
	if err := params.SetPlaintextModulus(65537); err != nil {
		log.Fatal("Failed to set plaintext modulus:", err)
	}

	// Set multiplicative depth (allow for operations)
	if err := params.SetMultiplicativeDepth(2); err != nil {
		log.Fatal("Failed to set multiplicative depth:", err)
	}

	// Generate crypto context
	cc, err := openfhe.NewCryptoContextBFV(params)
	if err != nil {
		log.Fatal("Failed to create crypto context:", err)
	}
	defer cc.Close()

	// Enable features including PRE
	fmt.Println("\nEnabling PKE, KEYSWITCH, LEVELEDSHE, and PRE features...")
	if err := cc.Enable(openfhe.PKE); err != nil {
		log.Fatal("Failed to enable PKE:", err)
	}
	if err := cc.Enable(openfhe.KEYSWITCH); err != nil {
		log.Fatal("Failed to enable KEYSWITCH:", err)
	}
	if err := cc.Enable(openfhe.LEVELEDSHE); err != nil {
		log.Fatal("Failed to enable LEVELEDSHE:", err)
	}
	if err := cc.Enable(openfhe.PRE); err != nil {
		log.Fatal("Failed to enable PRE:", err)
	}

	// Generate keys for Alice (data owner)
	fmt.Println("\nGenerating keys for Alice (data owner)...")
	aliceKeys, err := cc.KeyGen()
	if err != nil {
		log.Fatal("Failed to generate Alice's keys:", err)
	}
	defer aliceKeys.Close()

	// Generate keys for Bob (data recipient)
	fmt.Println("Generating keys for Bob (data recipient)...")
	bobKeys, err := cc.KeyGen()
	if err != nil {
		log.Fatal("Failed to generate Bob's keys:", err)
	}
	defer bobKeys.Close()

	// Alice creates her data (a vector of integers)
	vectorSize := 16
	aliceData := make([]int64, vectorSize)
	fmt.Println("\nAlice's original data:")
	for i := range aliceData {
		aliceData[i] = int64((i + 1) * 10)
		fmt.Printf("%d ", aliceData[i])
	}
	fmt.Println()

	// Create plaintext from Alice's data
	plaintext, err := cc.MakePackedPlaintext(aliceData)
	if err != nil {
		log.Fatal("Failed to create plaintext:", err)
	}
	defer plaintext.Close()

	// Alice encrypts her data
	fmt.Println("\nAlice encrypts her data...")
	ciphertext, err := cc.Encrypt(aliceKeys, plaintext)
	if err != nil {
		log.Fatal("Failed to encrypt:", err)
	}
	defer ciphertext.Close()

	// Verify Alice can decrypt her own data
	fmt.Println("Verifying Alice can decrypt her own data...")
	decryptedByAlice, err := cc.Decrypt(aliceKeys, ciphertext)
	if err != nil {
		log.Fatal("Failed to decrypt by Alice:", err)
	}
	defer decryptedByAlice.Close()

	resultAlice, err := decryptedByAlice.GetPackedValue()
	if err != nil {
		log.Fatal("Failed to get Alice's packed value:", err)
	}

	fmt.Println("Alice's decrypted data:")
	for i := 0; i < vectorSize; i++ {
		fmt.Printf("%d ", resultAlice[i])
	}
	fmt.Println()

	// Generate re-encryption key from Alice to Bob
	// This allows a proxy to transform Alice's ciphertext to Bob's encryption
	fmt.Println("\nGenerating re-encryption key from Alice to Bob...")
	reencryptionKey, err := cc.ReKeyGen(aliceKeys, bobKeys)
	if err != nil {
		log.Fatal("Failed to generate re-encryption key:", err)
	}
	defer reencryptionKey.Close()

	// Proxy performs re-encryption (transforms Alice's ciphertext to Bob's)
	fmt.Println("Proxy re-encrypts the ciphertext from Alice's key to Bob's key...")
	reencryptedCiphertext, err := cc.ReEncrypt(ciphertext, reencryptionKey)
	if err != nil {
		log.Fatal("Failed to re-encrypt:", err)
	}
	defer reencryptedCiphertext.Close()

	// Bob decrypts the re-encrypted ciphertext
	fmt.Println("Bob decrypts the re-encrypted ciphertext...")
	decryptedByBob, err := cc.Decrypt(bobKeys, reencryptedCiphertext)
	if err != nil {
		log.Fatal("Failed to decrypt by Bob:", err)
	}
	defer decryptedByBob.Close()

	resultBob, err := decryptedByBob.GetPackedValue()
	if err != nil {
		log.Fatal("Failed to get Bob's packed value:", err)
	}

	fmt.Println("Bob's decrypted data:")
	for i := 0; i < vectorSize; i++ {
		fmt.Printf("%d ", resultBob[i])
	}
	fmt.Println()

	// Verify Bob gets the same data as Alice
	fmt.Println("\nVerifying Bob received the correct data...")
	allMatch := true
	for i := 0; i < vectorSize; i++ {
		if resultBob[i] != aliceData[i] {
			fmt.Printf("Mismatch at index %d: expected %d, got %d\n",
				i, aliceData[i], resultBob[i])
			allMatch = false
		}
	}

	if allMatch {
		fmt.Println("✓ Success! Bob received Alice's data correctly via proxy re-encryption!")
	} else {
		fmt.Println("✗ Failed! Data mismatch detected.")
	}

	fmt.Println("\n===================================================")
	fmt.Println("PRE Buffer Example completed successfully!")
	fmt.Println("\nKey Concepts Demonstrated:")
	fmt.Println("1. Alice encrypts data with her public key")
	fmt.Println("2. Re-encryption key allows transformation without decryption")
	fmt.Println("3. Proxy transforms ciphertext from Alice's key to Bob's key")
	fmt.Println("4. Bob can decrypt with his private key")
	fmt.Println("5. Alice's data remains confidential throughout the process")
}
