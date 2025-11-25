package main

import (
	"fmt"
	"log"
	"math"
	"math/rand"

	"github.com/dozyio/openfhe-go/openfhe"
)

func must(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}

// CalculateApproximationError calculates the precision number (or approximation error).
// The higher the precision, the less the error.
// Using infinity norm as in the C++ example.
func calculateApproximationError(result, expected []float64) float64 {
	if len(result) != len(expected) {
		log.Fatal("Cannot compare vectors with different numbers of elements")
	}

	maxError := 0.0
	for i := range result {
		error := math.Abs(result[i] - expected[i])
		if maxError < error {
			maxError = error
		}
	}

	return math.Abs(math.Log2(maxError))
}

func main() {
	fmt.Println("--- Go iterative-ckks-bootstrapping ---")
	fmt.Println("Example for multiple iterations of CKKS bootstrapping to improve precision.")
	fmt.Println()

	// Step 1: Set CryptoContext parameters
	params, err := openfhe.NewParamsCKKSRNS()
	must(err, "NewParamsCKKSRNS")
	defer params.Close()

	must(params.SetSecretKeyDist(openfhe.SecretKeyUniformTernary), "SetSecretKeyDist")
	must(params.SetSecurityLevel(openfhe.HEStdNotSet), "SetSecurityLevel")
	must(params.SetRingDim(uint64(1<<12)), "SetRingDim") // 4096

	// 64-bit configuration
	must(params.SetScalingTechnique(openfhe.FLEXIBLEAUTO), "SetScalingTechnique")
	must(params.SetScalingModSize(59), "SetScalingModSize")
	must(params.SetFirstModSize(60), "SetFirstModSize")

	// Set batch size (number of slots) to 8
	must(params.SetBatchSize(8), "SetBatchSize")

	// Number of iterations to run bootstrapping
	// Currently only 1 or 2 iterations are supported
	// Two iterations should give approximately double the precision of one iteration
	numIterations := uint32(2)

	levelBudget := []uint32{3, 3}
	levelsAvailableAfterBootstrap := uint32(10)
	bootstrapDepth := openfhe.GetBootstrapDepth(levelBudget, openfhe.SecretKeyUniformTernary)
	depth := levelsAvailableAfterBootstrap + bootstrapDepth + (numIterations - 1)
	must(params.SetMultiplicativeDepth(int(depth)), "SetMultiplicativeDepth")

	// Step 2: Generate crypto context
	cc, err := openfhe.NewCryptoContextCKKS(params)
	must(err, "NewCryptoContextCKKS")
	defer cc.Close()

	// Enable features - FHE is required for bootstrapping
	must(cc.Enable(openfhe.PKE), "Enable PKE")
	must(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	must(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")
	must(cc.Enable(openfhe.ADVANCEDSHE), "Enable ADVANCEDSHE")
	must(cc.Enable(openfhe.FHE), "Enable FHE")

	ringDim := cc.GetRingDimension()
	fmt.Printf("CKKS scheme is using ring dimension %d\n\n", ringDim)

	// Step 3: Precomputations for bootstrapping
	// We use sparse packing with 8 slots
	numSlots := uint32(8)
	bsgsDim := []uint32{0, 0}
	must(cc.EvalBootstrapSetup(levelBudget, bsgsDim, numSlots), "EvalBootstrapSetup")

	// Step 4: Key Generation
	kp, err := cc.KeyGen()
	must(err, "KeyGen")
	defer kp.Close()

	must(cc.EvalMultKeyGen(kp), "EvalMultKeyGen")
	must(cc.EvalBootstrapKeyGen(kp, numSlots), "EvalBootstrapKeyGen")

	// Step 5: Encoding and encryption of inputs
	// Generate random input
	x := make([]float64, numSlots)
	for i := range x {
		x[i] = rand.Float64()
	}

	// We start with a depleted ciphertext that has used up all of its levels
	pt, err := cc.MakeCKKSPackedPlaintextWithParams(x, 1.0, int(depth-1))
	must(err, "MakeCKKSPackedPlaintextWithParams")
	defer pt.Close()

	must(pt.SetLength(int(numSlots)), "SetLength")
	fmt.Println("Input values:")
	for i, v := range x {
		fmt.Printf("  [%d] %.6f\n", i, v)
	}
	fmt.Println()

	// Encrypt the encoded vector
	ciph, err := cc.Encrypt(kp, pt)
	must(err, "Encrypt")
	defer ciph.Close()

	// Step 6: Measure the precision of a single bootstrapping operation
	fmt.Println("Running single iteration of bootstrapping to measure precision...")
	ciphertextAfter, err := cc.EvalBootstrap(ciph)
	must(err, "EvalBootstrap (single iteration)")
	defer ciphertextAfter.Close()

	result, err := cc.Decrypt(kp, ciphertextAfter)
	must(err, "Decrypt")
	defer result.Close()

	must(result.SetLength(int(numSlots)), "SetLength")
	got, err := result.GetRealPackedValue()
	must(err, "GetRealPackedValue")

	precision := uint32(math.Floor(calculateApproximationError(got[:numSlots], x)))
	fmt.Printf("Bootstrapping precision after 1 iteration: %d\n", precision)

	// For consistency with the C++ example, you might set precision to an empirically
	// measured value from many test runs. The C++ example uses 17.
	// Uncomment the line below to use a fixed value:
	// precision = 17
	fmt.Printf("Precision input to algorithm: %d\n\n", precision)

	// Step 7: Run bootstrapping with multiple iterations
	fmt.Printf("Running bootstrapping with %d iterations...\n", numIterations)
	ciphertextTwoIterations, err := cc.EvalBootstrapWithIterations(ciph, numIterations, precision)
	must(err, "EvalBootstrapWithIterations")
	defer ciphertextTwoIterations.Close()

	resultTwoIterations, err := cc.Decrypt(kp, ciphertextTwoIterations)
	must(err, "Decrypt two iterations")
	defer resultTwoIterations.Close()

	must(resultTwoIterations.SetLength(int(numSlots)), "SetLength")
	actualResult, err := resultTwoIterations.GetRealPackedValue()
	must(err, "GetRealPackedValue")

	fmt.Println("Output after two iterations of bootstrapping:")
	for i := 0; i < int(numSlots); i++ {
		fmt.Printf("  [%d] %.6f (expected %.6f, diff %.8f)\n",
			i, actualResult[i], x[i], math.Abs(actualResult[i]-x[i]))
	}
	fmt.Println()

	// Calculate and display the precision after multiple iterations
	precisionMultipleIterations := calculateApproximationError(actualResult[:numSlots], x)
	fmt.Printf("Bootstrapping precision after %d iterations: %.2f\n", numIterations, precisionMultipleIterations)

	// Calculate levels remaining after bootstrapping
	level, ok := ciphertextTwoIterations.GetLevel()
	if ok {
		noiseScaleDeg := ciphertextTwoIterations.GetNoiseScaleDeg()
		levelsRemaining := int(depth) - level - (int(noiseScaleDeg) - 1)
		fmt.Printf("Number of levels remaining after %d bootstrappings: %d\n", numIterations, levelsRemaining)
	}
	fmt.Println()

	// Summary
	fmt.Println("Summary:")
	fmt.Printf("  Single iteration precision:   %d\n", precision)
	fmt.Printf("  Multiple iteration precision: %.2f\n", precisionMultipleIterations)
	fmt.Printf("  Precision improvement:        %.2fx\n", precisionMultipleIterations/float64(precision))
	fmt.Println()
	fmt.Println("With 2 iterations, we achieve approximately double the precision of a single bootstrapping.")
}
