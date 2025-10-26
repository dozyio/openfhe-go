package main

import (
	"fmt"
	"log"

	"github.com/dozyio/openfhe-go/openfhe"
)

func main() {
	defer openfhe.Cleanup()

	fmt.Println("Starting BinFHE simple boolean example")

	// 1. Create BinFHE Context
	// We use STD128 for 128 bits of security and GINX for bootstrapping.
	cc := openfhe.NewBinFHEContext()
	cc.GenerateBinFHEContext(openfhe.STD128, openfhe.GINX)

	fmt.Println("BinFHE context generated.")

	// 2. Key Generation
	// Generate the secret key
	sk := cc.KeyGen()
	fmt.Println("Secret key generated.")

	// 3. Bootstrapping Key Generation
	// Generate the bootstrapping keys (refresh and switching)
	cc.BTKeyGen(sk)
	fmt.Println("Bootstrapping keys generated.")

	// 4. Encryption
	// Encrypt two booleans: 1 (true) and 0 (false)
	ct1 := cc.Encrypt(sk, 1)
	ct2 := cc.Encrypt(sk, 0)
	fmt.Println("Encrypted ct1 = 1, ct2 = 0")

	// 5. Homomorphic Operations
	// Perform AND, OR, and XOR
	fmt.Println("Running homomorphic operations...")
	ctAND := cc.EvalBinGate(openfhe.AND, ct1, ct2)
	ctOR := cc.EvalBinGate(openfhe.OR, ct1, ct2)
	ctXOR := cc.EvalBinGate(openfhe.XOR, ct1, ct2)

	// 6. Homomorphic Bootstrapping (Refresh)
	// Refresh the ciphertext for ct1
	ctRefresh := cc.Bootstrap(ct1)
	fmt.Println("Bootstrapping (Refresh) complete.")

	// 7. Decryption
	fmt.Println("Decrypting results...")
	var resultAND, resultOR, resultXOR, resultRefresh int

	resultAND = cc.Decrypt(sk, ctAND)
	resultOR = cc.Decrypt(sk, ctOR)
	resultXOR = cc.Decrypt(sk, ctXOR)
	resultRefresh = cc.Decrypt(sk, ctRefresh)

	// 8. Check Results
	fmt.Printf("Plaintext 1: 1, Plaintext 2: 0\n")
	fmt.Printf("Result AND (1 & 0): %d\n", resultAND)
	fmt.Printf("Result OR (1 | 0):  %d\n", resultOR)
	fmt.Printf("Result XOR (1 ^ 0): %d\n", resultXOR)
	fmt.Printf("Result Refresh(1):  %d\n", resultRefresh)

	if resultAND != 0 {
		log.Fatalf("Error: AND(1, 0) != 0")
	}
	if resultOR != 1 {
		log.Fatalf("Error: OR(1, 0) != 1")
	}
	if resultXOR != 1 {
		log.Fatalf("Error: XOR(1, 0) != 1")
	}
	if resultRefresh != 1 {
		log.Fatalf("Error: Refresh(1) != 1")
	}

	fmt.Println("\nAll boolean operations and refresh worked correctly!")
}
