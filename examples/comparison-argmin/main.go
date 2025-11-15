package main

import (
	"fmt"
	"log"
	"math"

	"github.com/dozyio/openfhe-go/openfhe"
)

// This example demonstrates finding minimum/maximum values and their indices
// (argmin/argmax) on encrypted data using scheme switching.
//
// Use case: Finding outliers or extremes in encrypted datasets without decryption.
// For example: finding the highest/lowest temperature in encrypted sensor readings.

func main() {
	fmt.Println("Comparison Operations - Finding Min/Max with Argmin/Argmax")
	fmt.Println("============================================================")

	// Setup CKKS parameters for scheme switching
	scaleModSize := 50
	firstModSize := 60
	ringDim := uint64(65536) // HE standard compliant
	slots := uint32(8)
	numValues := uint32(8)

	// Calculate required multiplicative depth
	// Depth needed: 13 for FHEW to CKKS, log2(numValues) for argmin/argmax
	multDepth := 9 + 3 + 1 + int(math.Log2(float64(numValues)))

	fmt.Printf("\nSetup Parameters:\n")
	fmt.Printf("  Ring Dimension: %d\n", ringDim)
	fmt.Printf("  Slots: %d\n", slots)
	fmt.Printf("  Values to Compare: %d\n", numValues)
	fmt.Printf("  Multiplicative Depth: %d\n", multDepth)

	params, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		log.Fatal("Failed to create CKKS parameters:", err)
	}
	defer params.Close()

	if err := params.SetMultiplicativeDepth(multDepth); err != nil {
		log.Fatal("Failed to set multiplicative depth:", err)
	}
	if err := params.SetScalingModSize(scaleModSize); err != nil {
		log.Fatal("Failed to set scaling mod size:", err)
	}
	if err := params.SetFirstModSize(firstModSize); err != nil {
		log.Fatal("Failed to set first mod size:", err)
	}
	if err := params.SetRingDim(ringDim); err != nil {
		log.Fatal("Failed to set ring dimension:", err)
	}
	if err := params.SetBatchSize(int(slots)); err != nil {
		log.Fatal("Failed to set batch size:", err)
	}

	cc, err := openfhe.NewCryptoContextCKKS(params)
	if err != nil {
		log.Fatal("Failed to create crypto context:", err)
	}
	defer cc.Close()

	// Enable required features
	fmt.Println("\nEnabling Features...")
	if err := cc.Enable(openfhe.PKE); err != nil {
		log.Fatal("Failed to enable PKE:", err)
	}
	if err := cc.Enable(openfhe.KEYSWITCH); err != nil {
		log.Fatal("Failed to enable KEYSWITCH:", err)
	}
	if err := cc.Enable(openfhe.LEVELEDSHE); err != nil {
		log.Fatal("Failed to enable LEVELEDSHE:", err)
	}
	if err := cc.Enable(openfhe.ADVANCEDSHE); err != nil {
		log.Fatal("Failed to enable ADVANCEDSHE:", err)
	}
	if err := cc.Enable(openfhe.SCHEMESWITCH); err != nil {
		log.Fatal("Failed to enable SCHEMESWITCH:", err)
	}

	// Generate keys
	fmt.Println("Generating Keys...")
	keys, err := cc.KeyGen()
	if err != nil {
		log.Fatal("Failed to generate keys:", err)
	}
	defer keys.Close()

	if err := cc.EvalMultKeyGen(keys); err != nil {
		log.Fatal("Failed to generate multiplication keys:", err)
	}

	// Setup scheme switching (required for comparisons)
	fmt.Println("Setting up Scheme Switching (CKKS ↔ FHEW)...")
	swParams, err := openfhe.NewSchSwchParams()
	if err != nil {
		log.Fatal("Failed to create scheme switch params:", err)
	}
	// Set security levels (using weak parameters for demo - use HEStd128Classic and BinFHESTD128 in production)
	if err := swParams.SetSecurityLevelCKKS(openfhe.HEStdNotSet); err != nil {
		log.Fatal("Failed to set CKKS security level:", err)
	}
	if err := swParams.SetSecurityLevelFHEW(openfhe.BinFHETOY); err != nil {
		log.Fatal("Failed to set FHEW security level:", err)
	}
	if err := swParams.SetNumSlotsCKKS(slots); err != nil {
		log.Fatal("Failed to set num slots:", err)
	}
	if err := swParams.SetNumValues(numValues); err != nil {
		log.Fatal("Failed to set num values:", err)
	}
	if err := swParams.SetComputeArgmin(true); err != nil {
		log.Fatal("Failed to enable argmin computation:", err)
	}
	if err := swParams.SetCtxtModSizeFHEWLargePrec(25); err != nil {
		log.Fatal("Failed to set FHEW ciphertext modulus size:", err)
	}
	defer swParams.Close()

	// Bidirectional scheme switching setup (includes bootstrapping key generation)
	lwesk, err := cc.EvalSchemeSwitchingSetup(swParams)
	if err != nil {
		log.Fatal("Failed to setup scheme switching:", err)
	}
	defer lwesk.Close()

	if err := cc.EvalSchemeSwitchingKeyGen(keys, lwesk); err != nil {
		log.Fatal("Failed to generate scheme switching keys:", err)
	}

	// Get FHEW context and compute parameters for comparison operations
	ccLWE, err := cc.GetBinCCForSchemeSwitch()
	if err != nil {
		log.Fatal("Failed to get BinFHE context:", err)
	}

	// Use large precision for comparisons
	modulus_LWE := uint32(1 << 25) // logQ_ccLWE = 25
	beta, err := ccLWE.GetBeta()
	if err != nil {
		log.Fatal("Failed to get beta:", err)
	}
	pLWE := modulus_LWE / (2 * beta)
	scaleSign := 512.0

	if err := cc.EvalCompareSwitchPrecompute(pLWE, scaleSign); err != nil {
		log.Fatal("Failed to precompute comparison parameters:", err)
	}

	fmt.Printf("  FHEW plaintext modulus: %d\n", pLWE)
	fmt.Printf("  Scale sign: %.1f\n", scaleSign)

	// Example: Temperature readings from encrypted sensors (in Celsius)
	temperatures := []float64{23.5, 19.2, 31.7, 15.3, 28.4, 18.9, 25.6, 33.2}

	fmt.Printf("\nOriginal Temperature Data (°C):\n")
	for i, temp := range temperatures {
		fmt.Printf("  Sensor %d: %.1f°C\n", i, temp)
	}

	// Encrypt the data
	fmt.Println("\nEncrypting temperature data...")
	plaintext, err := cc.MakeCKKSPackedPlaintext(temperatures)
	if err != nil {
		log.Fatal("Failed to create plaintext:", err)
	}
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	if err != nil {
		log.Fatal("Failed to encrypt:", err)
	}
	defer ciphertext.Close()

	fmt.Println("✓ Data encrypted successfully")

	// Find MINIMUM temperature (coldest sensor)
	fmt.Println("\n--- Finding MINIMUM Temperature (Coldest Sensor) ---")
	minResult, err := cc.EvalMinSchemeSwitching(ciphertext, keys, numValues, slots)
	if err != nil {
		log.Fatal("Failed to find minimum:", err)
	}
	defer minResult.Close()

	// Decrypt minimum value
	minPlaintext, err := cc.Decrypt(keys, minResult.Value)
	if err != nil {
		log.Fatal("Failed to decrypt min value:", err)
	}
	defer minPlaintext.Close()

	minPlaintext.SetLength(1)
	minValues, err := minPlaintext.GetRealPackedValue()
	if err != nil {
		log.Fatal("Failed to get min value:", err)
	}

	// Extract argmin index from one-hot encoded result
	minIndex, err := minResult.GetIndexFromOneHot(cc, keys, numValues)
	if err != nil {
		log.Fatal("Failed to get argmin index:", err)
	}

	minTemp := minValues[0]

	fmt.Printf("✓ Minimum Temperature: %.1f°C\n", minTemp)
	fmt.Printf("✓ Coldest Sensor: Sensor %d\n", minIndex)

	// Find MAXIMUM temperature (hottest sensor)
	fmt.Println("\n--- Finding MAXIMUM Temperature (Hottest Sensor) ---")
	maxResult, err := cc.EvalMaxSchemeSwitching(ciphertext, keys, numValues, slots)
	if err != nil {
		log.Fatal("Failed to find maximum:", err)
	}
	defer maxResult.Close()

	// Decrypt maximum value
	maxPlaintext, err := cc.Decrypt(keys, maxResult.Value)
	if err != nil {
		log.Fatal("Failed to decrypt max value:", err)
	}
	defer maxPlaintext.Close()

	maxPlaintext.SetLength(1)
	maxValues, err := maxPlaintext.GetRealPackedValue()
	if err != nil {
		log.Fatal("Failed to get max value:", err)
	}

	// Extract argmax index from one-hot encoded result
	maxIndex, err := maxResult.GetIndexFromOneHot(cc, keys, numValues)
	if err != nil {
		log.Fatal("Failed to get argmax index:", err)
	}

	maxTemp := maxValues[0]

	fmt.Printf("✓ Maximum Temperature: %.1f°C\n", maxTemp)
	fmt.Printf("✓ Hottest Sensor: Sensor %d\n", maxIndex)

	// Summary
	fmt.Println("\n============================================================")
	fmt.Println("Summary:")
	fmt.Printf("  Temperature Range: %.1f°C to %.1f°C\n", minTemp, maxTemp)
	fmt.Printf("  Temperature Spread: %.1f°C\n", maxTemp-minTemp)
	fmt.Printf("  Coldest Location: Sensor %d\n", minIndex)
	fmt.Printf("  Hottest Location: Sensor %d\n", maxIndex)

	fmt.Println("\n✓ Comparison operations completed successfully!")
	fmt.Println("\nKey Concepts Demonstrated:")
	fmt.Println("1. Finding min/max on encrypted data without decryption")
	fmt.Println("2. Identifying indices (argmin/argmax) of extreme values")
	fmt.Println("3. Using scheme switching (CKKS ↔ FHEW) for exact comparisons")
	fmt.Println("4. Practical use case: monitoring encrypted sensor data")
}
