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
	fmt.Println("Starting BinFHE boolean example with LMKCDEY bootstrapping")

	// Sample Program: Step 1: Set CryptoContext

	cc, err := openfhe.NewBinFHEContext()
	checkErr(err, "Creating context")
	defer cc.Close()

	// We use the STD128_LMKCDEY setting optimized for the LMKCDEY mode.
	// LMKCDEY is a bootstrapping method that provides an alternative to
	// AP and GINX methods. It is optimized for certain parameter sets.
	err = cc.GenerateBinFHEContext(openfhe.STD128_LMKCDEY, openfhe.LMKCDEY)
	checkErr(err, "Generating context parameters")

	// Sample Program: Step 2: Key Generation

	// Generate the secret key
	sk, err := cc.KeyGen()
	checkErr(err, "Generating secret key")
	defer sk.Close()

	fmt.Println("Generating the bootstrapping keys...")

	// Generate the bootstrapping keys (refresh and switching keys)
	err = cc.BTKeyGen(sk)
	checkErr(err, "Generating bootstrapping keys")

	fmt.Println("Completed the key generation.")

	// Sample Program: Step 3: Encryption

	// Encrypt two ciphertexts representing Boolean True (1)
	// By default, freshly encrypted ciphertexts are bootstrapped.
	// If you wish to get a fresh encryption without bootstrapping, write
	// auto ct1 = cc.Encrypt(sk, 1, LARGE_DIM);
	ct1, err := cc.Encrypt(sk, 1)
	checkErr(err, "Encrypting ct1")
	defer ct1.Close()

	ct2, err := cc.Encrypt(sk, 1)
	checkErr(err, "Encrypting ct2")
	defer ct2.Close()

	// Sample Program: Step 4: Evaluation

	// Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
	ctAND1, err := cc.EvalBinGate(openfhe.AND, ct1, ct2)
	checkErr(err, "Evaluating AND gate")
	defer ctAND1.Close()

	// Compute (NOT 1) = 0
	ct2Not, err := cc.EvalNOT(ct2)
	checkErr(err, "Evaluating NOT gate")
	defer ct2Not.Close()

	// Compute (1 AND (NOT 1)) = 0
	ctAND2, err := cc.EvalBinGate(openfhe.AND, ct2Not, ct1)
	checkErr(err, "Evaluating second AND gate")
	defer ctAND2.Close()

	// Computes OR of the results in ctAND1 and ctAND2 = 1
	ctResult, err := cc.EvalBinGate(openfhe.OR, ctAND1, ctAND2)
	checkErr(err, "Evaluating OR gate")
	defer ctResult.Close()

	// Sample Program: Step 5: Decryption

	result, err := cc.Decrypt(sk, ctResult)
	checkErr(err, "Decrypting result")

	fmt.Printf("Result of encrypted computation of (1 AND 1) OR (1 AND (NOT 1)) = %d\n", result)

	if result != 1 {
		log.Fatalf("Error: Expected result = 1, got %d", result)
	}

	fmt.Println("\nBoolean LMKCDEY bootstrapping example completed successfully!")
}
