package main

import (
	"fmt"
	"log"
	"math"

	// Complex numbers aren't directly supported by MakeCKKSPackedPlaintext in the provided API
	// "math/cmplx"

	"github.com/dozyio/openfhe-go/openfhe"
)

// Helper function to print vectors and check results (using float64)
func printAndCheck(label string, ptxt openfhe.Plaintext, expected []float64, tolerance float64, numSlots int) {
	// API Correction: Use GetRealPackedValue for CKKS
	result, err := ptxt.GetRealPackedValue()
	if err != nil {
		log.Fatalf("Error getting packed real value: %v", err)
	}

	fmt.Printf("%s: ", label)
	count := 10 // Print first few values
	if numSlots < count {
		count = numSlots
	}
	fmt.Printf("[")
	for i := 0; i < count; i++ {
		// Handle potential index out of range if result length < count
		if i >= len(result) {
			break
		}
		// Print real part only
		fmt.Printf("%.6f", result[i])
		if i < count-1 && i < len(result)-1 {
			fmt.Printf(", ")
		}
	}
	fmt.Printf("...]\n")

	// Check precision
	var maxError float64 = 0
	checkCount := numSlots
	if len(result) < checkCount {
		checkCount = len(result)
	}
	if len(expected) < checkCount {
		checkCount = len(expected)
	}

	for i := 0; i < checkCount; i++ {
		// Use math.Abs for float64 difference
		errVal := math.Abs(result[i] - expected[i])
		if errVal > maxError {
			maxError = errVal
		}
	}
	fmt.Printf("Maximum error: %.6g\n", maxError)
	if maxError > tolerance {
		fmt.Printf("WARNING: Max error exceeds tolerance %.6g\n", tolerance)
	} else {
		fmt.Printf("Results are within tolerance %.6g\n", tolerance)
	}
	fmt.Println("--------------------")
}

func main() {
	fmt.Println("Advanced CKKS Example for x^3 using manual rescaling")
	fmt.Println("====================================================")

	// Step 1: Set CryptoContext Parameters
	// API Correction: Parameter setters expect int
	multiplicativeDepth := 2
	scalingModSize := 50
	batchSize := 8

	// API Correction: Use NewParamsCKKSRNS()
	parameters, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		log.Fatalf("Failed to create parameters: %v", err)
	}
	defer parameters.Close() // Close params when done

	// API Correction: Pass ints directly
	err = parameters.SetMultiplicativeDepth(multiplicativeDepth)
	if err != nil {
		log.Fatalf("SetMultiplicativeDepth failed: %v", err)
	}
	err = parameters.SetScalingModSize(scalingModSize)
	if err != nil {
		log.Fatalf("SetScalingModSize failed: %v", err)
	}
	err = parameters.SetBatchSize(batchSize)
	if err != nil {
		log.Fatalf("SetBatchSize failed: %v", err)
	}
	// API Correction: Scaling technique constant uses int type in Go
	err = parameters.SetScalingTechnique(openfhe.FIXEDMANUAL)
	if err != nil {
		log.Fatalf("SetScalingTechnique failed: %v", err)
	}

	// Step 2: Generate CryptoContext
	// API Correction: Use NewCryptoContextCKKS
	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	if err != nil {
		log.Fatalf("Failed to create CryptoContext: %v", err)
	}
	defer cc.Close() // Close context when done

	// API Correction: Feature flags are int constants
	err = cc.Enable(openfhe.PKE)
	if err != nil {
		log.Fatalf("Enable PKE failed: %v", err)
	}
	err = cc.Enable(openfhe.KEYSWITCH)
	if err != nil {
		log.Fatalf("Enable KEYSWITCH failed: %v", err)
	}
	err = cc.Enable(openfhe.LEVELEDSHE)
	if err != nil {
		log.Fatalf("Enable LEVELEDSHE failed: %v", err)
	}

	fmt.Printf("CKKS scheme is using ring dimension %d\n", cc.GetRingDimension())
	// API Correction: GetSecurityLevel does not exist
	fmt.Println("--------------------")

	// Step 3: Key Generation
	// API Correction: KeyGen returns (*KeyPair, error)
	keys, err := cc.KeyGen()
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}
	defer keys.Close() // Close keys when done

	// API Correction: EvalMultKeyGen takes *KeyPair
	err = cc.EvalMultKeyGen(keys)
	if err != nil {
		log.Fatalf("EvalMultKeyGen failed: %v", err)
	}

	// Step 4: Encoding and Encryption
	// API Correction: Use []float64 for MakeCKKSPackedPlaintext
	x := make([]float64, batchSize)
	expectedX3 := make([]float64, batchSize)
	for i := 0; i < batchSize; i++ {
		val := 1.0 + 0.1*float64(i)
		x[i] = val
		expectedX3[i] = math.Pow(val, 3)
	}

	// API Correction: Use MakeCKKSPackedPlaintext(vec []float64)
	ptxt, err := cc.MakeCKKSPackedPlaintext(x)
	if err != nil {
		log.Fatalf("MakeCKKSPackedPlaintext failed: %v", err)
	}
	defer ptxt.Close() // Close plaintext when done
	fmt.Printf("Input vector x:         %.6f, ...\n", x[0])

	// API Correction: Encrypt takes *KeyPair, returns (*Ciphertext, error)
	ciphertext, err := cc.Encrypt(keys, ptxt)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	defer ciphertext.Close() // Close ciphertext when done

	level, ok := ciphertext.GetLevel()
	if !ok {
		log.Fatalf("GetLevel failed")
	}

	fmt.Printf("Initial ciphertext level: %d\n", level) // GetLevel() seems 0-indexed in C++
	fmt.Println("--------------------")

	// Step 5: Homomorphic Computations (x^3 = x*x*x)

	fmt.Println("Computing cMult1 = ciphertext * ciphertext (x^2)...")
	// API Correction: EvalMult returns (*Ciphertext, error)
	cMult1, err := cc.EvalMult(ciphertext, ciphertext)
	if err != nil {
		log.Fatalf("First EvalMult failed: %v", err)
	}
	defer cMult1.Close()

	level, ok = cMult1.GetLevel()
	if !ok {
		log.Fatalf("cMult1 GetLevel failed")
	}
	fmt.Printf("Level after first EvalMult: %d\n", level)

	fmt.Println("Rescaling cMult1...")
	// API Correction: Rescale returns (*Ciphertext, error)
	cRescaled1, err := cc.Rescale(cMult1)
	if err != nil {
		log.Fatalf("First Rescale failed: %v", err)
	}
	defer cRescaled1.Close()

	level, ok = cRescaled1.GetLevel()
	if !ok {
		log.Fatalf("cRescaled1 GetLevel failed")
	}
	fmt.Printf("Level after Rescale: %d\n", level)

	fmt.Println("Computing cMult2 = cRescaled1 * ciphertext (x^3)...")
	// API Correction: EvalMult returns (*Ciphertext, error)
	cMult2, err := cc.EvalMult(cRescaled1, ciphertext)
	if err != nil {
		// Potential Level Mismatch: If EvalMult strictly requires same level,
		// we might need to ModReduce or LevelReduce 'ciphertext' here.
		// Let's assume for now it handles it or they are implicitly at same level after rescale.
		log.Fatalf("Second EvalMult failed: %v", err)
	}
	defer cMult2.Close()
	level, ok = cMult2.GetLevel()
	if !ok {
		log.Fatalf("cMult2 GetLevel failed")
	}
	fmt.Printf("Level after second EvalMult: %d\n", level)

	fmt.Println("Rescaling cMult2...")
	// API Correction: Rescale returns (*Ciphertext, error)
	cResult, err := cc.Rescale(cMult2)
	if err != nil {
		log.Fatalf("Second Rescale failed: %v", err)
	}
	defer cResult.Close() // This is the final result ciphertext
	level, ok = cResult.GetLevel()
	if !ok {
		log.Fatalf("cResult GetLevel failed")
	}
	fmt.Printf("Final ciphertext level: %d\n", level)
	fmt.Println("--------------------")

	// Step 6: Decryption and Decoding
	// API Correction: Decrypt takes *KeyPair, returns (*Plaintext, error)
	decryptedPtxt, err := cc.Decrypt(keys, cResult)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	defer decryptedPtxt.Close() // Close decrypted plaintext

	// API Correction: Plaintext.SetLength takes int
	err = decryptedPtxt.SetLength(batchSize) // Use int
	if err != nil {
		log.Fatalf("SetLength failed: %v", err)
	}

	tolerance := 0.001
	printAndCheck("Decrypted x^3", *decryptedPtxt, expectedX3, tolerance, batchSize)

	fmt.Println("Execution finished.")
}
