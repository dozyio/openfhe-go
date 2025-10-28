package main

import (
	"fmt"
	"log"

	"github.com/dozyio/openfhe-go/openfhe"
)

// Helper for error checking
func checkErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

func main() {
	fmt.Println("Starting BinFHE simple boolean example")

	// 1. Create BinFHE Context
	cc, err := openfhe.NewBinFHEContext()
	checkErr(err, "Creating context")
	defer cc.Close() // Ensure context is closed on exit

	err = cc.GenerateBinFHEContext(openfhe.STD128, openfhe.GINX)
	checkErr(err, "Generating context parameters")
	fmt.Println("BinFHE context generated.")

	// 2. Key Generation
	sk, err := cc.KeyGen()
	checkErr(err, "Generating secret key")
	defer sk.Close() // Ensure secret key is closed on exit
	fmt.Println("Secret key generated.")

	// 3. Bootstrapping Key Generation
	err = cc.BTKeyGen(sk)
	checkErr(err, "Generating bootstrapping keys")
	fmt.Println("Bootstrapping keys generated.")

	// 4. Encryption
	ct1, err := cc.Encrypt(sk, 1)
	checkErr(err, "Encrypting ct1")
	defer ct1.Close() // Use defer for simplicity if scope allows, or manual Close later

	ct2, err := cc.Encrypt(sk, 0)
	checkErr(err, "Encrypting ct2")
	defer ct2.Close()

	fmt.Println("Encrypted ct1 = 1, ct2 = 0")

	// 5. Homomorphic Operations
	fmt.Println("Running homomorphic operations...")
	ctAND, err := cc.EvalBinGate(openfhe.AND, ct1, ct2)
	checkErr(err, "Evaluating AND gate")
	defer ctAND.Close()

	ctOR, err := cc.EvalBinGate(openfhe.OR, ct1, ct2)
	checkErr(err, "Evaluating OR gate")
	defer ctOR.Close()

	ctXOR, err := cc.EvalBinGate(openfhe.XOR, ct1, ct2)
	checkErr(err, "Evaluating XOR gate")
	defer ctXOR.Close()

	// 6. Homomorphic Bootstrapping (Refresh)
	ctRefresh, err := cc.Bootstrap(ct1)
	checkErr(err, "Bootstrapping ct1")
	defer ctRefresh.Close()
	fmt.Println("Bootstrapping (Refresh) complete.")

	// 7. Decryption
	fmt.Println("Decrypting results...")
	var resultAND, resultOR, resultXOR, resultRefresh int

	resultAND, err = cc.Decrypt(sk, ctAND)
	checkErr(err, "Decrypting AND result")

	resultOR, err = cc.Decrypt(sk, ctOR)
	checkErr(err, "Decrypting OR result")

	resultXOR, err = cc.Decrypt(sk, ctXOR)
	checkErr(err, "Decrypting XOR result")

	resultRefresh, err = cc.Decrypt(sk, ctRefresh)
	checkErr(err, "Decrypting Refresh result")

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
