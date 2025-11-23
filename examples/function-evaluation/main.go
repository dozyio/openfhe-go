package main

import (
	"fmt"
	"math"

	"github.com/dozyio/openfhe-go/openfhe"
)

func evalLogisticExample() {
	fmt.Println("--------------------------------- EVAL LOGISTIC FUNCTION ---------------------------------")

	params, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		panic(err)
	}
	defer params.Close()

	// We set a smaller ring dimension to improve performance for this example.
	// In production environments, the security level should be set to
	// HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
	// or 256-bit security, respectively.
	if err := params.SetSecurityLevel(openfhe.HEStdNotSet); err != nil {
		panic(err)
	}
	if err := params.SetRingDim(1 << 10); err != nil {
		panic(err)
	}

	scalingModSize := 50
	firstModSize := 60

	if err := params.SetScalingModSize(scalingModSize); err != nil {
		panic(err)
	}
	if err := params.SetFirstModSize(firstModSize); err != nil {
		panic(err)
	}

	// Choosing a higher degree yields better precision, but a longer runtime.
	polyDegree := uint32(16)

	// The multiplicative depth depends on the polynomial degree.
	// See the FUNCTION_EVALUATION.md file for a table mapping polynomial degrees to multiplicative depths.
	multDepth := 6

	if err := params.SetMultiplicativeDepth(multDepth); err != nil {
		panic(err)
	}

	cc, err := openfhe.NewCryptoContextCKKS(params)
	if err != nil {
		panic(err)
	}
	defer cc.Close()

	if err := cc.Enable(openfhe.PKE); err != nil {
		panic(err)
	}
	if err := cc.Enable(openfhe.KEYSWITCH); err != nil {
		panic(err)
	}
	if err := cc.Enable(openfhe.LEVELEDSHE); err != nil {
		panic(err)
	}
	// We need to enable Advanced SHE to use the Chebyshev approximation.
	if err := cc.Enable(openfhe.ADVANCEDSHE); err != nil {
		panic(err)
	}

	keyPair, err := cc.KeyGen()
	if err != nil {
		panic(err)
	}
	defer keyPair.Close()

	// We need to generate mult keys to run Chebyshev approximations.
	if err := cc.EvalMultKeyGen(keyPair); err != nil {
		panic(err)
	}

	input := []float64{-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0}
	encodedLength := len(input)

	plaintext, err := cc.MakeCKKSPackedPlaintext(input)
	if err != nil {
		panic(err)
	}
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keyPair, plaintext)
	if err != nil {
		panic(err)
	}
	defer ciphertext.Close()

	lowerBound := -5.0
	upperBound := 5.0

	result, err := cc.EvalLogistic(ciphertext, lowerBound, upperBound, polyDegree)
	if err != nil {
		panic(err)
	}
	defer result.Close()

	plaintextDec, err := cc.Decrypt(keyPair, result)
	if err != nil {
		panic(err)
	}
	defer plaintextDec.Close()

	if err := plaintextDec.SetLength(encodedLength); err != nil {
		panic(err)
	}

	expectedOutput := []float64{0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011}
	fmt.Printf("Expected output\n\t%v\n", expectedOutput)

	finalResult, err := plaintextDec.GetRealPackedValue()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Actual output\n\t%v\n\n", finalResult[:encodedLength])

	// Verify accuracy
	fmt.Println("Verification:")
	maxError := 0.0
	for i := 0; i < encodedLength; i++ {
		error := math.Abs(finalResult[i] - expectedOutput[i])
		if error > maxError {
			maxError = error
		}
		fmt.Printf("  Input: %6.1f  Expected: %.6f  Got: %.6f  Error: %.6f\n",
			input[i], expectedOutput[i], finalResult[i], error)
	}
	fmt.Printf("Maximum error: %.6f\n\n", maxError)
}

func main() {
	fmt.Println("Example of evaluating arbitrary smooth functions with the Chebyshev approximation using CKKS.")
	fmt.Println()
	fmt.Println("This example demonstrates EvalLogistic, which evaluates the logistic function 1/(1+exp(-x)).")
	fmt.Println()
	evalLogisticExample()
	fmt.Println("Function evaluation example completed successfully!")
}
