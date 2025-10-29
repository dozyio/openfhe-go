package main

import (
	"fmt"
	"log"
	"math"
	"os"

	"github.com/dozyio/openfhe-go/openfhe"
)

// poly is the plaintext function we want to evaluate homomorphically.
// f(x) = 1 + 2x + 3x^2
func poly(x float64) float64 {
	return 1 + 2*x + 3*x*x
}

func main() {
	fmt.Println("--- OpenFHE Go Example: Polynomial Evaluation ---")

	// --- Setup: Parameters ---
	parameters, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		log.Fatalf("Failed to create CKKS parameters: %v", err)
	}
	defer parameters.Close()

	// Set parameters
	multDepth := uint32(6)
	scaleModSize := 50

	err = parameters.SetMultiplicativeDepth(int(multDepth))
	if err != nil {
		log.Fatalf("Failed SetMultiplicativeDepth: %v", err)
	}

	err = parameters.SetScalingModSize(scaleModSize)
	if err != nil {
		log.Fatalf("Failed SetScalingModSize: %v", err)
	}

	fmt.Printf("CKKS parameters: MultDepth=%d, ScaleModSize=%d\n", multDepth, scaleModSize)

	// --- Setup: CryptoContext ---
	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	if err != nil {
		log.Fatalf("Failed NewCryptoContextCKKS: %v", err)
	}
	defer cc.Close()
	fmt.Println("CryptoContext generated.")

	// Enable features
	cc.Enable(openfhe.PKE)
	cc.Enable(openfhe.KEYSWITCH)
	cc.Enable(openfhe.LEVELEDSHE)
	cc.Enable(openfhe.ADVANCEDSHE)
	fmt.Println("Features enabled: PKE, KEYSWITCH, LEVELEDSHE, ADVANCEDSHE.")

	// --- Setup: Keys ---
	keys, err := cc.KeyGen()
	if err != nil {
		log.Fatalf("Failed KeyGen: %v", err)
	}
	defer keys.Close()

	err = cc.EvalMultKeyGen(keys)
	if err != nil {
		log.Fatalf("Failed EvalMultKeyGen: %v", err)
	}
	fmt.Println("Keys generated.")

	// --- Input and Encryption ---
	input := []float64{0.5, 0.7, 0.9, 1.1}

	ptx, err := cc.MakeCKKSPackedPlaintext(input)
	if err != nil {
		log.Fatalf("Failed MakeCKKSPackedPlaintext: %v", err)
	}
	defer ptx.Close()
	fmt.Printf("Input Plaintext (first few): %.4f, %.4f, ...\n", input[0], input[1])

	ctx, err := cc.Encrypt(keys, ptx)
	if err != nil {
		log.Fatalf("Failed Encrypt: %v", err)
	}
	defer ctx.Close()
	fmt.Println("Input encrypted.")

	// --- Homomorphic Polynomial Evaluation ---
	coefficients := []float64{1.0, 2.0, 3.0}

	fmt.Printf("Evaluating polynomial with coefficients: %v\n", coefficients)
	ctxResult, err := cc.EvalPoly(ctx, coefficients)
	if err != nil {
		log.Fatalf("❌ Error during EvalPoly: %v", err)
	}
	defer ctxResult.Close()
	fmt.Println("Polynomial evaluated homomorphically.")

	// --- Decryption and Verification ---
	ptxResult, err := cc.Decrypt(keys, ctxResult)
	if err != nil {
		log.Fatalf("Failed Decrypt: %v", err)
	}
	defer ptxResult.Close()

	resultVec, err := ptxResult.GetRealPackedValue()
	if err != nil {
		log.Fatalf("Failed GetRealPackedValue: %v", err)
	}
	fmt.Println("Result decrypted.")

	// --- Comparison ---
	expected := make([]float64, len(input))
	for i, val := range input {
		expected[i] = poly(val)
	}

	fmt.Println("\n--- Results Comparison ---")
	fmt.Printf(" Input | Expected | Got      | Diff\n")
	fmt.Println("-------|----------|----------|-----------")
	precision := 1e-4
	passed := true
	displayCount := 4
	if len(input) < displayCount {
		displayCount = len(input)
	}

	for i := 0; i < displayCount; i++ {
		var gotVal float64
		if i < len(resultVec) {
			gotVal = resultVec[i]
		} else {
			gotVal = math.NaN()
		}

		diff := math.Abs(expected[i] - gotVal)
		status := "✅"
		if diff > precision || math.IsNaN(gotVal) {
			status = "❌"
			passed = false
		}
		fmt.Printf(" %5.2f | %8.4f | %8.4f | %9.2e %s\n", input[i], expected[i], gotVal, diff, status)
	}
	if len(input) > displayCount {
		fmt.Println(" ... (results truncated)")
	}
	if len(resultVec) < len(input) {
		fmt.Println("Warning: Result vector shorter than input vector.")
		passed = false
	}

	if !passed {
		fmt.Println("\n❌ Polynomial Evaluation FAILED.")
		os.Exit(1)
	}
	fmt.Println("\n✅ Polynomial Evaluation Successful!")
}
