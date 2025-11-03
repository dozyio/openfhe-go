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

func main() { //nolint:funlen // Example demonstrates all truth tables systematically
	fmt.Println("Starting BinFHE Boolean Truth Tables Example")

	// Sample Program: Step 1: Set CryptoContext
	cc, err := openfhe.NewBinFHEContext()
	checkErr(err, "Creating context")
	defer cc.Close()

	fmt.Println("Generate cryptocontext")

	// STD128 is the security level of 128 bits of security based on LWE Estimator
	// and HE standard. Other options are TOY, MEDIUM, STD192, and STD256. MEDIUM
	// corresponds to the level of more than 100 bits for both quantum and
	// classical computer attacks.
	err = cc.GenerateBinFHEContext(openfhe.STD128, openfhe.GINX)
	checkErr(err, "Generating context parameters")
	fmt.Println("Finished generating cryptocontext")

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

	// Encrypt two ciphertexts representing Boolean True (1).
	ct10, err := cc.Encrypt(sk, 1)
	checkErr(err, "Encrypting ct10")
	defer ct10.Close()

	ct11, err := cc.Encrypt(sk, 1)
	checkErr(err, "Encrypting ct11")
	defer ct11.Close()

	// Encrypt two ciphertexts representing Boolean False (0).
	ct00, err := cc.Encrypt(sk, 0)
	checkErr(err, "Encrypting ct00")
	defer ct00.Close()

	ct01, err := cc.Encrypt(sk, 0)
	checkErr(err, "Encrypting ct01")
	defer ct01.Close()

	// Sample Program: Step 4: Evaluation of NAND gates

	fmt.Println("NAND Truth Table:")
	ctNAND1, err := cc.EvalBinGate(openfhe.NAND, ct10, ct11)
	checkErr(err, "Evaluating NAND(1,1)")
	defer ctNAND1.Close()

	ctNAND2, err := cc.EvalBinGate(openfhe.NAND, ct10, ct01)
	checkErr(err, "Evaluating NAND(1,0)")
	defer ctNAND2.Close()

	ctNAND3, err := cc.EvalBinGate(openfhe.NAND, ct00, ct01)
	checkErr(err, "Evaluating NAND(0,0)")
	defer ctNAND3.Close()

	ctNAND4, err := cc.EvalBinGate(openfhe.NAND, ct00, ct11)
	checkErr(err, "Evaluating NAND(0,1)")
	defer ctNAND4.Close()

	result, err := cc.Decrypt(sk, ctNAND1)
	checkErr(err, "Decrypting NAND(1,1)")
	fmt.Printf("1 NAND 1 = %d\n", result)

	result, err = cc.Decrypt(sk, ctNAND2)
	checkErr(err, "Decrypting NAND(1,0)")
	fmt.Printf("1 NAND 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctNAND3)
	checkErr(err, "Decrypting NAND(0,0)")
	fmt.Printf("0 NAND 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctNAND4)
	checkErr(err, "Decrypting NAND(0,1)")
	fmt.Printf("0 NAND 1 = %d\n\n", result)

	// Sample Program: Step 5: Evaluation of AND gates

	fmt.Println("AND Truth Table:")
	ctAND1, err := cc.EvalBinGate(openfhe.AND, ct10, ct11)
	checkErr(err, "Evaluating AND(1,1)")
	defer ctAND1.Close()

	ctAND2, err := cc.EvalBinGate(openfhe.AND, ct10, ct01)
	checkErr(err, "Evaluating AND(1,0)")
	defer ctAND2.Close()

	ctAND3, err := cc.EvalBinGate(openfhe.AND, ct00, ct01)
	checkErr(err, "Evaluating AND(0,0)")
	defer ctAND3.Close()

	ctAND4, err := cc.EvalBinGate(openfhe.AND, ct00, ct11)
	checkErr(err, "Evaluating AND(0,1)")
	defer ctAND4.Close()

	result, err = cc.Decrypt(sk, ctAND1)
	checkErr(err, "Decrypting AND(1,1)")
	fmt.Printf("1 AND 1 = %d\n", result)

	result, err = cc.Decrypt(sk, ctAND2)
	checkErr(err, "Decrypting AND(1,0)")
	fmt.Printf("1 AND 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctAND3)
	checkErr(err, "Decrypting AND(0,0)")
	fmt.Printf("0 AND 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctAND4)
	checkErr(err, "Decrypting AND(0,1)")
	fmt.Printf("0 AND 1 = %d\n\n", result)

	// Sample Program: Step 6: Evaluation of OR gates

	fmt.Println("OR Truth Table:")
	ctOR1, err := cc.EvalBinGate(openfhe.OR, ct10, ct11)
	checkErr(err, "Evaluating OR(1,1)")
	defer ctOR1.Close()

	ctOR2, err := cc.EvalBinGate(openfhe.OR, ct10, ct01)
	checkErr(err, "Evaluating OR(1,0)")
	defer ctOR2.Close()

	ctOR3, err := cc.EvalBinGate(openfhe.OR, ct00, ct01)
	checkErr(err, "Evaluating OR(0,0)")
	defer ctOR3.Close()

	ctOR4, err := cc.EvalBinGate(openfhe.OR, ct00, ct11)
	checkErr(err, "Evaluating OR(0,1)")
	defer ctOR4.Close()

	result, err = cc.Decrypt(sk, ctOR1)
	checkErr(err, "Decrypting OR(1,1)")
	fmt.Printf("1 OR 1 = %d\n", result)

	result, err = cc.Decrypt(sk, ctOR2)
	checkErr(err, "Decrypting OR(1,0)")
	fmt.Printf("1 OR 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctOR3)
	checkErr(err, "Decrypting OR(0,0)")
	fmt.Printf("0 OR 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctOR4)
	checkErr(err, "Decrypting OR(0,1)")
	fmt.Printf("0 OR 1 = %d\n\n", result)

	// Sample Program: Step 7: Evaluation of NOR gates

	fmt.Println("NOR Truth Table:")
	ctNOR1, err := cc.EvalBinGate(openfhe.NOR, ct10, ct11)
	checkErr(err, "Evaluating NOR(1,1)")
	defer ctNOR1.Close()

	ctNOR2, err := cc.EvalBinGate(openfhe.NOR, ct10, ct01)
	checkErr(err, "Evaluating NOR(1,0)")
	defer ctNOR2.Close()

	ctNOR3, err := cc.EvalBinGate(openfhe.NOR, ct00, ct01)
	checkErr(err, "Evaluating NOR(0,0)")
	defer ctNOR3.Close()

	ctNOR4, err := cc.EvalBinGate(openfhe.NOR, ct00, ct11)
	checkErr(err, "Evaluating NOR(0,1)")
	defer ctNOR4.Close()

	result, err = cc.Decrypt(sk, ctNOR1)
	checkErr(err, "Decrypting NOR(1,1)")
	fmt.Printf("1 NOR 1 = %d\n", result)

	result, err = cc.Decrypt(sk, ctNOR2)
	checkErr(err, "Decrypting NOR(1,0)")
	fmt.Printf("1 NOR 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctNOR3)
	checkErr(err, "Decrypting NOR(0,0)")
	fmt.Printf("0 NOR 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctNOR4)
	checkErr(err, "Decrypting NOR(0,1)")
	fmt.Printf("0 NOR 1 = %d\n\n", result)

	// Sample Program: Step 8: Evaluation of XOR gates

	fmt.Println("XOR Truth Table:")
	ctXOR1, err := cc.EvalBinGate(openfhe.XOR, ct10, ct11)
	checkErr(err, "Evaluating XOR(1,1)")
	defer ctXOR1.Close()

	ctXOR2, err := cc.EvalBinGate(openfhe.XOR, ct10, ct01)
	checkErr(err, "Evaluating XOR(1,0)")
	defer ctXOR2.Close()

	ctXOR3, err := cc.EvalBinGate(openfhe.XOR, ct00, ct01)
	checkErr(err, "Evaluating XOR(0,0)")
	defer ctXOR3.Close()

	ctXOR4, err := cc.EvalBinGate(openfhe.XOR, ct00, ct11)
	checkErr(err, "Evaluating XOR(0,1)")
	defer ctXOR4.Close()

	result, err = cc.Decrypt(sk, ctXOR1)
	checkErr(err, "Decrypting XOR(1,1)")
	fmt.Printf("1 XOR 1 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXOR2)
	checkErr(err, "Decrypting XOR(1,0)")
	fmt.Printf("1 XOR 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXOR3)
	checkErr(err, "Decrypting XOR(0,0)")
	fmt.Printf("0 XOR 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXOR4)
	checkErr(err, "Decrypting XOR(0,1)")
	fmt.Printf("0 XOR 1 = %d\n\n", result)

	// Sample Program: Step 9: Evaluation of XNOR gates

	fmt.Println("XNOR Truth Table:")
	ctXNOR1, err := cc.EvalBinGate(openfhe.XNOR, ct10, ct11)
	checkErr(err, "Evaluating XNOR(1,1)")
	defer ctXNOR1.Close()

	ctXNOR2, err := cc.EvalBinGate(openfhe.XNOR, ct10, ct01)
	checkErr(err, "Evaluating XNOR(1,0)")
	defer ctXNOR2.Close()

	ctXNOR3, err := cc.EvalBinGate(openfhe.XNOR, ct00, ct01)
	checkErr(err, "Evaluating XNOR(0,0)")
	defer ctXNOR3.Close()

	ctXNOR4, err := cc.EvalBinGate(openfhe.XNOR, ct00, ct11)
	checkErr(err, "Evaluating XNOR(0,1)")
	defer ctXNOR4.Close()

	result, err = cc.Decrypt(sk, ctXNOR1)
	checkErr(err, "Decrypting XNOR(1,1)")
	fmt.Printf("1 XNOR 1 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXNOR2)
	checkErr(err, "Decrypting XNOR(1,0)")
	fmt.Printf("1 XNOR 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXNOR3)
	checkErr(err, "Decrypting XNOR(0,0)")
	fmt.Printf("0 XNOR 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXNOR4)
	checkErr(err, "Decrypting XNOR(0,1)")
	fmt.Printf("0 XNOR 1 = %d\n\n", result)

	// Sample Program: Step 10: Evaluation of XOR_FAST gates
	// Note: XOR_FAST is included for backwards compatibility and maps to XOR

	fmt.Println("XOR_FAST Truth Table:")
	ctXORFAST1, err := cc.EvalBinGate(openfhe.XOR_FAST, ct10, ct11)
	checkErr(err, "Evaluating XOR_FAST(1,1)")
	defer ctXORFAST1.Close()

	ctXORFAST2, err := cc.EvalBinGate(openfhe.XOR_FAST, ct10, ct01)
	checkErr(err, "Evaluating XOR_FAST(1,0)")
	defer ctXORFAST2.Close()

	ctXORFAST3, err := cc.EvalBinGate(openfhe.XOR_FAST, ct00, ct01)
	checkErr(err, "Evaluating XOR_FAST(0,0)")
	defer ctXORFAST3.Close()

	ctXORFAST4, err := cc.EvalBinGate(openfhe.XOR_FAST, ct00, ct11)
	checkErr(err, "Evaluating XOR_FAST(0,1)")
	defer ctXORFAST4.Close()

	result, err = cc.Decrypt(sk, ctXORFAST1)
	checkErr(err, "Decrypting XOR_FAST(1,1)")
	fmt.Printf("1 XOR_FAST 1 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXORFAST2)
	checkErr(err, "Decrypting XOR_FAST(1,0)")
	fmt.Printf("1 XOR_FAST 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXORFAST3)
	checkErr(err, "Decrypting XOR_FAST(0,0)")
	fmt.Printf("0 XOR_FAST 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXORFAST4)
	checkErr(err, "Decrypting XOR_FAST(0,1)")
	fmt.Printf("0 XOR_FAST 1 = %d\n\n", result)

	// Sample Program: Step 11: Evaluation of XNOR_FAST gates
	// Note: XNOR_FAST is included for backwards compatibility and maps to XNOR

	fmt.Println("XNOR_FAST Truth Table:")
	ctXNORFAST1, err := cc.EvalBinGate(openfhe.XNOR_FAST, ct10, ct11)
	checkErr(err, "Evaluating XNOR_FAST(1,1)")
	defer ctXNORFAST1.Close()

	ctXNORFAST2, err := cc.EvalBinGate(openfhe.XNOR_FAST, ct10, ct01)
	checkErr(err, "Evaluating XNOR_FAST(1,0)")
	defer ctXNORFAST2.Close()

	ctXNORFAST3, err := cc.EvalBinGate(openfhe.XNOR_FAST, ct00, ct01)
	checkErr(err, "Evaluating XNOR_FAST(0,0)")
	defer ctXNORFAST3.Close()

	ctXNORFAST4, err := cc.EvalBinGate(openfhe.XNOR_FAST, ct00, ct11)
	checkErr(err, "Evaluating XNOR_FAST(0,1)")
	defer ctXNORFAST4.Close()

	result, err = cc.Decrypt(sk, ctXNORFAST1)
	checkErr(err, "Decrypting XNOR_FAST(1,1)")
	fmt.Printf("1 XNOR_FAST 1 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXNORFAST2)
	checkErr(err, "Decrypting XNOR_FAST(1,0)")
	fmt.Printf("1 XNOR_FAST 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXNORFAST3)
	checkErr(err, "Decrypting XNOR_FAST(0,0)")
	fmt.Printf("0 XNOR_FAST 0 = %d\n", result)

	result, err = cc.Decrypt(sk, ctXNORFAST4)
	checkErr(err, "Decrypting XNOR_FAST(0,1)")
	fmt.Printf("0 XNOR_FAST 1 = %d\n\n", result)

	fmt.Println("All boolean truth table operations completed successfully!")
}
