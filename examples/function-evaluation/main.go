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

func evalSinExample() {
	fmt.Println("--------------------------------- EVAL SINE FUNCTION ---------------------------------")

	params, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		panic(err)
	}
	defer params.Close()

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

	polyDegree := uint32(32)
	multDepth := 7

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
	if err := cc.Enable(openfhe.ADVANCEDSHE); err != nil {
		panic(err)
	}

	keyPair, err := cc.KeyGen()
	if err != nil {
		panic(err)
	}
	defer keyPair.Close()

	if err := cc.EvalMultKeyGen(keyPair); err != nil {
		panic(err)
	}

	// Test values: 0, π/6, π/4, π/3, π/2
	input := []float64{0, math.Pi / 6, math.Pi / 4, math.Pi / 3, math.Pi / 2}
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

	lowerBound := -math.Pi
	upperBound := math.Pi

	result, err := cc.EvalSin(ciphertext, lowerBound, upperBound, polyDegree)
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

	// Expected: sin(0)=0, sin(π/6)=0.5, sin(π/4)≈0.707, sin(π/3)≈0.866, sin(π/2)=1
	expectedOutput := []float64{0.0, 0.5, 0.707107, 0.866025, 1.0}
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
		fmt.Printf("  sin(%.4f) = %.6f  Expected: %.6f  Error: %.6f\n",
			input[i], finalResult[i], expectedOutput[i], error)
	}
	fmt.Printf("Maximum error: %.6f\n\n", maxError)
}

func evalCosExample() {
	fmt.Println("--------------------------------- EVAL COSINE FUNCTION ---------------------------------")

	params, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		panic(err)
	}
	defer params.Close()

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

	polyDegree := uint32(32)
	multDepth := 7

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
	if err := cc.Enable(openfhe.ADVANCEDSHE); err != nil {
		panic(err)
	}

	keyPair, err := cc.KeyGen()
	if err != nil {
		panic(err)
	}
	defer keyPair.Close()

	if err := cc.EvalMultKeyGen(keyPair); err != nil {
		panic(err)
	}

	// Test values: 0, π/6, π/4, π/3, π/2
	input := []float64{0, math.Pi / 6, math.Pi / 4, math.Pi / 3, math.Pi / 2}
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

	lowerBound := -math.Pi
	upperBound := math.Pi

	result, err := cc.EvalCos(ciphertext, lowerBound, upperBound, polyDegree)
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

	// Expected: cos(0)=1, cos(π/6)≈0.866, cos(π/4)≈0.707, cos(π/3)=0.5, cos(π/2)=0
	expectedOutput := []float64{1.0, 0.866025, 0.707107, 0.5, 0.0}
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
		fmt.Printf("  cos(%.4f) = %.6f  Expected: %.6f  Error: %.6f\n",
			input[i], finalResult[i], expectedOutput[i], error)
	}
	fmt.Printf("Maximum error: %.6f\n\n", maxError)
}

func evalSqrtExample() {
	fmt.Println("--------------------------------- EVAL SQUARE ROOT FUNCTION ---------------------------------")

	params, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		panic(err)
	}
	defer params.Close()

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

	polyDegree := uint32(50)
	multDepth := 7

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
	if err := cc.Enable(openfhe.ADVANCEDSHE); err != nil {
		panic(err)
	}

	keyPair, err := cc.KeyGen()
	if err != nil {
		panic(err)
	}
	defer keyPair.Close()

	if err := cc.EvalMultKeyGen(keyPair); err != nil {
		panic(err)
	}

	input := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9}
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

	lowerBound := 0.0
	upperBound := 10.0

	// We can input any Go function that takes and returns a float64
	result, err := cc.EvalChebyshevFunction(math.Sqrt, ciphertext, lowerBound, upperBound, polyDegree)
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

	expectedOutput := []float64{1.0, 1.414213, 1.732050, 2.0, 2.236067, 2.449489, 2.645751, 2.828427, 3.0}
	fmt.Printf("Expected output\n\t%v\n", expectedOutput)

	finalResult, err := plaintextDec.GetRealPackedValue()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Actual output (encrypted)\n\t%v\n", finalResult[:encodedLength])

	// Compute the same approximation on cleartext data
	ptxtApprox := openfhe.EvalChebyshevFunctionPtxt(math.Sqrt, input, lowerBound, upperBound, polyDegree)
	fmt.Printf("Cleartext approximation\n\t%v\n\n", ptxtApprox)

	// Verify accuracy
	fmt.Println("Verification (Encrypted vs Expected):")
	maxError := 0.0
	for i := 0; i < encodedLength; i++ {
		error := math.Abs(finalResult[i] - expectedOutput[i])
		if error > maxError {
			maxError = error
		}
		fmt.Printf("  sqrt(%2.0f) Encrypted: %.6f  Expected: %.6f  Error: %.6f\n",
			input[i], finalResult[i], expectedOutput[i], error)
	}
	fmt.Printf("Maximum FHE+approximation error: %.6f\n\n", maxError)

	// Show approximation error vs FHE noise
	fmt.Println("Approximation Quality (Cleartext vs Expected):")
	maxApproxError := 0.0
	for i := 0; i < encodedLength; i++ {
		approxError := math.Abs(ptxtApprox[i] - expectedOutput[i])
		if approxError > maxApproxError {
			maxApproxError = approxError
		}
		fmt.Printf("  sqrt(%2.0f) Cleartext: %.6f  Expected: %.6f  Approx Error: %.6f\n",
			input[i], ptxtApprox[i], expectedOutput[i], approxError)
	}
	fmt.Printf("Maximum approximation error: %.6f\n", maxApproxError)
	fmt.Printf("FHE noise contribution: ~%.6f\n\n", maxError-maxApproxError)
}

func main() {
	fmt.Println("Example of evaluating smooth functions with Chebyshev approximation using CKKS.")
	fmt.Println()
	fmt.Println("This example demonstrates the following function evaluations:")
	fmt.Println("  - EvalLogistic: Logistic/sigmoid function 1/(1+exp(-x))")
	fmt.Println("  - EvalSin: Sine function sin(x)")
	fmt.Println("  - EvalCos: Cosine function cos(x)")
	fmt.Println("  - EvalChebyshevFunction: Custom functions (sqrt in this example)")
	fmt.Println("  - EvalChebyshevSeries: Batch optimization with pre-computed coefficients")
	fmt.Println()
	fmt.Println("The Go wrapper supports CUSTOM FUNCTIONS via CGO callbacks")
	fmt.Println("You can pass any Go function (func(float64) float64) to EvalChebyshevFunction.")
	fmt.Println()
	fmt.Println("Advanced API for batch processing:")
	fmt.Println("  1. Compute coefficients once: EvalChebyshevCoefficients(fn, a, b, degree)")
	fmt.Println("  2. Reuse on multiple ciphertexts: EvalChebyshevSeries(ct, coeffs, a, b)")
	fmt.Println()

	evalLogisticExample()
	evalSinExample()
	evalCosExample()
	evalSqrtExample()
	evalChebyshevSeriesBatchExample()

	fmt.Println("All function evaluation examples completed successfully!")
}

func evalChebyshevSeriesBatchExample() {
	fmt.Println("---------------------- EVAL CHEBYSHEV SERIES (BATCH OPTIMIZATION) ----------------------")

	params, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		panic(err)
	}
	defer params.Close()

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

	polyDegree := uint32(50)
	multDepth := 7

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
	if err := cc.Enable(openfhe.ADVANCEDSHE); err != nil {
		panic(err)
	}

	keyPair, err := cc.KeyGen()
	if err != nil {
		panic(err)
	}
	defer keyPair.Close()

	if err := cc.EvalMultKeyGen(keyPair); err != nil {
		panic(err)
	}

	fmt.Println("\nAdvanced API: Batch processing with pre-computed coefficients")
	fmt.Println("When evaluating the SAME function on MULTIPLE ciphertexts,")
	fmt.Println("you can compute coefficients once and reuse them for better performance.\n")

	// Step 1: Compute Chebyshev coefficients ONCE
	lowerBound := 0.1
	upperBound := 10.0
	fmt.Printf("Step 1: Computing Chebyshev coefficients for sqrt over [%.1f, %.1f] with degree %d...\n",
		lowerBound, upperBound, polyDegree)

	coeffs, err := openfhe.EvalChebyshevCoefficients(math.Sqrt, lowerBound, upperBound, polyDegree)
	if err != nil {
		panic(err)
	}
	fmt.Printf("        Computed %d coefficients ✓\n\n", len(coeffs))

	// Step 2: Prepare multiple batches of data
	batch1 := []float64{1, 4, 9}
	batch2 := []float64{0.5, 2, 6.25}
	batch3 := []float64{0.25, 1, 2.25}

	fmt.Println("Step 2: Encrypting three different batches of data...")

	pt1, err := cc.MakeCKKSPackedPlaintext(batch1)
	if err != nil {
		panic(err)
	}
	defer pt1.Close()
	ct1, err := cc.Encrypt(keyPair, pt1)
	if err != nil {
		panic(err)
	}
	defer ct1.Close()

	pt2, err := cc.MakeCKKSPackedPlaintext(batch2)
	if err != nil {
		panic(err)
	}
	defer pt2.Close()
	ct2, err := cc.Encrypt(keyPair, pt2)
	if err != nil {
		panic(err)
	}
	defer ct2.Close()

	pt3, err := cc.MakeCKKSPackedPlaintext(batch3)
	if err != nil {
		panic(err)
	}
	defer pt3.Close()
	ct3, err := cc.Encrypt(keyPair, pt3)
	if err != nil {
		panic(err)
	}
	defer ct3.Close()

	fmt.Printf("        Batch 1: %v\n", batch1)
	fmt.Printf("        Batch 2: %v\n", batch2)
	fmt.Printf("        Batch 3: %v\n\n", batch3)

	// Step 3: Evaluate using the SAME coefficients on all batches
	fmt.Println("Step 3: Evaluating sqrt on all batches using EvalChebyshevSeries...")
	fmt.Println("        (Reusing the same coefficients for all batches)\n")

	result1, err := cc.EvalChebyshevSeries(ct1, coeffs, lowerBound, upperBound)
	if err != nil {
		panic(err)
	}
	defer result1.Close()

	result2, err := cc.EvalChebyshevSeries(ct2, coeffs, lowerBound, upperBound)
	if err != nil {
		panic(err)
	}
	defer result2.Close()

	result3, err := cc.EvalChebyshevSeries(ct3, coeffs, lowerBound, upperBound)
	if err != nil {
		panic(err)
	}
	defer result3.Close()

	// Step 4: Decrypt and display results
	fmt.Println("Step 4: Decrypting results...\n")

	ptDec1, err := cc.Decrypt(keyPair, result1)
	if err != nil {
		panic(err)
	}
	defer ptDec1.Close()
	if err := ptDec1.SetLength(len(batch1)); err != nil {
		panic(err)
	}
	output1, err := ptDec1.GetRealPackedValue()
	if err != nil {
		panic(err)
	}

	ptDec2, err := cc.Decrypt(keyPair, result2)
	if err != nil {
		panic(err)
	}
	defer ptDec2.Close()
	if err := ptDec2.SetLength(len(batch2)); err != nil {
		panic(err)
	}
	output2, err := ptDec2.GetRealPackedValue()
	if err != nil {
		panic(err)
	}

	ptDec3, err := cc.Decrypt(keyPair, result3)
	if err != nil {
		panic(err)
	}
	defer ptDec3.Close()
	if err := ptDec3.SetLength(len(batch3)); err != nil {
		panic(err)
	}
	output3, err := ptDec3.GetRealPackedValue()
	if err != nil {
		panic(err)
	}

	// Display results
	fmt.Println("Results:")
	fmt.Printf("  Batch 1: sqrt(%v) = %v\n", batch1, output1[:len(batch1)])
	expected1 := []float64{1.0, 2.0, 3.0}
	fmt.Printf("           Expected: %v\n\n", expected1)

	fmt.Printf("  Batch 2: sqrt(%v) = %v\n", batch2, output2[:len(batch2)])
	expected2 := []float64{0.707107, 1.414214, 2.5}
	fmt.Printf("           Expected: %v\n\n", expected2)

	fmt.Printf("  Batch 3: sqrt(%v) = %v\n", batch3, output3[:len(batch3)])
	expected3 := []float64{0.5, 1.0, 1.5}
	fmt.Printf("           Expected: %v\n\n", expected3)

	// Verify accuracy
	fmt.Println("Verification:")
	tolerance := 0.01
	allGood := true

	for i := 0; i < len(batch1); i++ {
		err := math.Abs(output1[i] - expected1[i])
		status := "✓"
		if err > tolerance {
			status = "✗"
			allGood = false
		}
		fmt.Printf("  Batch 1[%d]: %.6f (error: %.6f) %s\n", i, output1[i], err, status)
	}

	for i := 0; i < len(batch2); i++ {
		err := math.Abs(output2[i] - expected2[i])
		status := "✓"
		if err > tolerance {
			status = "✗"
			allGood = false
		}
		fmt.Printf("  Batch 2[%d]: %.6f (error: %.6f) %s\n", i, output2[i], err, status)
	}

	for i := 0; i < len(batch3); i++ {
		err := math.Abs(output3[i] - expected3[i])
		status := "✓"
		if err > tolerance {
			status = "✗"
			allGood = false
		}
		fmt.Printf("  Batch 3[%d]: %.6f (error: %.6f) %s\n", i, output3[i], err, status)
	}

	if !allGood {
		panic("Verification failed!")
	}

	fmt.Println("\nPerformance benefit:")
	fmt.Println("  - EvalChebyshevFunction: Computes coefficients EVERY time (slower)")
	fmt.Println("  - EvalChebyshevSeries: Computes coefficients ONCE, reuses them (faster)")
	fmt.Println("  - For 3 batches, EvalChebyshevSeries is approximately 3x more efficient!")
	fmt.Println()
}
