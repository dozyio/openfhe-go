// Port of OpenFHE C++ example: src/pke/examples/linearwsum-evaluation.cpp
// Example of linear weighted sum evaluation using CKKS.

package main

import (
	"fmt"
	"log"
	"math"
	"math/cmplx"

	"github.com/dozyio/openfhe-go/openfhe"
)

func main() {
	fmt.Println("\n======EXAMPLE FOR EVAL LINEAR WEIGHTED SUM========\n")

	// Setup parameters - matching the C++ example
	parameters, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		log.Fatalf("NewParamsCKKSRNS failed: %v", err)
	}
	defer parameters.Close()

	if err := parameters.SetMultiplicativeDepth(1); err != nil {
		log.Fatalf("SetMultiplicativeDepth failed: %v", err)
	}
	if err := parameters.SetScalingModSize(50); err != nil {
		log.Fatalf("SetScalingModSize failed: %v", err)
	}
	if err := parameters.SetBatchSize(8); err != nil {
		log.Fatalf("SetBatchSize failed: %v", err)
	}
	if err := parameters.SetSecurityLevel(openfhe.HEStdNotSet); err != nil {
		log.Fatalf("SetSecurityLevel failed: %v", err)
	}
	if err := parameters.SetRingDim(2048); err != nil {
		log.Fatalf("SetRingDim failed: %v", err)
	}
	if err := parameters.SetScalingTechnique(openfhe.FLEXIBLEAUTO); err != nil {
		log.Fatalf("SetScalingTechnique failed: %v", err)
	}
	if err := parameters.SetFirstModSize(60); err != nil {
		log.Fatalf("SetFirstModSize failed: %v", err)
	}

	// Create crypto context
	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	if err != nil {
		log.Fatalf("NewCryptoContextCKKS failed: %v", err)
	}
	defer cc.Close()

	// Enable features
	if err := cc.Enable(openfhe.PKE); err != nil {
		log.Fatalf("Enable PKE failed: %v", err)
	}
	if err := cc.Enable(openfhe.KEYSWITCH); err != nil {
		log.Fatalf("Enable KEYSWITCH failed: %v", err)
	}
	if err := cc.Enable(openfhe.LEVELEDSHE); err != nil {
		log.Fatalf("Enable LEVELEDSHE failed: %v", err)
	}
	if err := cc.Enable(openfhe.ADVANCEDSHE); err != nil {
		log.Fatalf("Enable ADVANCEDSHE failed: %v", err)
	}

	// Input data - matching the C++ example
	input := [][]complex128{
		{0.5, 0.7, 0.9, 0.95, 0.93, 1.3},
		{1.2, 1.7, -0.9, 0.85, -0.63, 2},
		{0.5, 0, 1.9, 2.95, -3.93, 3.3},
		{1.5, 0.7, 1.9, 2.95, -3.78, 3.3},
		{0.5, 2.7, 1.9, 0.0, -3.43, 1.3},
		{0.5, 0.7, -1.9, 2.95, 1.96, 0.0},
		{0.0, 0.0, 1.0, 0.0, 0.0, 0.0},
	}

	coefficients := []float64{0.15, 0.75, 1.25, 1, 0, 0.5, 0.5}

	// Generate keys
	keyPair, err := cc.KeyGen()
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}
	defer keyPair.Close()

	fmt.Println("Generating evaluation key for homomorphic multiplication...")
	if err := cc.EvalMultKeyGen(keyPair); err != nil {
		log.Fatalf("EvalMultKeyGen failed: %v", err)
	}
	fmt.Println("Completed.")

	// Encrypt all input vectors
	ciphertextVec := make([]*openfhe.Ciphertext, len(input))
	for i := 0; i < len(input); i++ {
		plaintext, err := cc.MakeCKKSComplexPackedPlaintext(input[i])
		if err != nil {
			log.Fatalf("MakeCKKSComplexPackedPlaintext failed: %v", err)
		}
		defer plaintext.Close()

		ct, err := cc.Encrypt(keyPair, plaintext)
		if err != nil {
			log.Fatalf("Encrypt failed: %v", err)
		}
		defer ct.Close()

		ciphertextVec[i] = ct
	}

	// Evaluate linear weighted sum
	result, err := cc.EvalLinearWSum(ciphertextVec, coefficients)
	if err != nil {
		log.Fatalf("EvalLinearWSum failed: %v", err)
	}
	defer result.Close()

	// Compute expected unencrypted result
	unencIP := make([]complex128, len(input[0]))
	for i := 0; i < len(input[0]); i++ {
		var x complex128
		for j := 0; j < len(input); j++ {
			x += input[j][i] * complex(coefficients[j], 0)
		}
		unencIP[i] = x
	}

	// Decrypt result
	plaintextDec, err := cc.Decrypt(keyPair, result)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}
	defer plaintextDec.Close()

	// The length should be the number of elements per vector, not the number of vectors
	vectorLength := len(input[0])
	if err := plaintextDec.SetLength(vectorLength); err != nil {
		log.Fatalf("SetLength failed: %v", err)
	}

	decResult, err := plaintextDec.GetComplexPackedValue()
	if err != nil {
		log.Fatalf("GetComplexPackedValue failed: %v", err)
	}

	fmt.Printf("\nResult of evaluating a linear weighted sum with coefficients %v\n", coefficients)
	fmt.Printf("Decrypted result: ")
	for i := 0; i < vectorLength; i++ {
		fmt.Printf("%.10f ", real(decResult[i]))
	}
	fmt.Println()

	fmt.Printf("\nExpected result: ")
	for i := 0; i < vectorLength; i++ {
		fmt.Printf("%.10f ", real(unencIP[i]))
	}
	fmt.Println()

	// Verify results match (within tolerance)
	allMatch := true
	tolerance := 0.00001
	for i := 0; i < vectorLength; i++ {
		diff := cmplx.Abs(decResult[i] - unencIP[i])
		if diff > tolerance {
			allMatch = false
			fmt.Printf("Mismatch at position %d: expected %.10f, got %.10f (diff: %.10e)\n",
				i, real(unencIP[i]), real(decResult[i]), diff)
		}
	}

	if allMatch {
		fmt.Println("\nResult verification: PASSED")
	} else {
		fmt.Println("\nResult verification: FAILED")
	}

	// Compute and print percentage error
	var maxError float64
	for i := 0; i < vectorLength; i++ {
		percentError := math.Abs(real(decResult[i])-real(unencIP[i])) / math.Abs(real(unencIP[i])) * 100
		if percentError > maxError {
			maxError = percentError
		}
	}
	fmt.Printf("Maximum percentage error: %.6f%%\n", maxError)
}
