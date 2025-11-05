package main

import (
	"fmt"
	"log"
	"math"

	"github.com/dozyio/openfhe-go/openfhe"
)

func main() {
	fmt.Println("=== OpenFHE Scheme Switching Example ===\n")

	// This example demonstrates switching between CKKS (approximate arithmetic)
	// and FHEW (boolean/small integer operations) schemes

	if err := runSchemeSwitchingExample(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n=== Example completed successfully! ===")
}

func runSchemeSwitchingExample() error {
	fmt.Println("Step 1: Setting up CKKS CryptoContext")

	// CKKS parameters
	multDepth := 3
	firstModSize := 60
	scaleModSize := 50
	ringDim := uint64(4096)
	slots := 8 // Use fewer slots for faster execution
	batchSize := slots

	params, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		return fmt.Errorf("NewParamsCKKSRNS: %w", err)
	}
	defer params.Close()

	if err := params.SetMultiplicativeDepth(multDepth); err != nil {
		return err
	}
	if err := params.SetFirstModSize(firstModSize); err != nil {
		return err
	}
	if err := params.SetScalingModSize(scaleModSize); err != nil {
		return err
	}
	if err := params.SetScalingTechnique(openfhe.FIXEDMANUAL); err != nil {
		return err
	}
	if err := params.SetSecurityLevel(openfhe.HEStdNotSet); err != nil {
		return err
	}
	if err := params.SetRingDim(ringDim); err != nil {
		return err
	}
	if err := params.SetBatchSize(batchSize); err != nil {
		return err
	}

	cc, err := openfhe.NewCryptoContextCKKS(params)
	if err != nil {
		return fmt.Errorf("NewCryptoContextCKKS: %w", err)
	}
	defer cc.Close()

	// Enable features including SCHEMESWITCH
	if err := cc.Enable(openfhe.PKE); err != nil {
		return err
	}
	if err := cc.Enable(openfhe.KEYSWITCH); err != nil {
		return err
	}
	if err := cc.Enable(openfhe.LEVELEDSHE); err != nil {
		return err
	}
	if err := cc.Enable(openfhe.SCHEMESWITCH); err != nil {
		return err
	}

	fmt.Printf("  Ring dimension: %d\n", cc.GetRingDimension())
	fmt.Printf("  Slots: %d\n", slots)
	fmt.Printf("  Multiplicative depth: %d\n\n", multDepth)

	fmt.Println("Step 2: Generating keys")
	keys, err := cc.KeyGen()
	if err != nil {
		return fmt.Errorf("KeyGen: %w", err)
	}
	defer keys.Close()

	fmt.Println("Step 3: Setting up scheme switching")

	// Configure scheme switching parameters
	swParams, err := openfhe.NewSchSwchParams()
	if err != nil {
		return fmt.Errorf("NewSchSwchParams: %w", err)
	}
	defer swParams.Close()

	if err := swParams.SetSecurityLevelCKKS(openfhe.HEStdNotSet); err != nil {
		return err
	}
	if err := swParams.SetSecurityLevelFHEW(openfhe.BinFHETOY); err != nil {
		return err
	}
	if err := swParams.SetNumSlotsCKKS(uint32(slots)); err != nil {
		return err
	}
	if err := swParams.SetCtxtModSizeFHEWLargePrec(25); err != nil {
		return err
	}
	if err := swParams.SetNumValues(uint32(slots)); err != nil {
		return err
	}

	// Setup CKKS to FHEW switching
	lwesk, err := cc.EvalCKKStoFHEWSetup(swParams)
	if err != nil {
		return fmt.Errorf("EvalCKKStoFHEWSetup: %w", err)
	}
	defer lwesk.Close()

	// Get BinFHE context
	// Note: This context is owned by the CKKS context and should NOT be closed
	ccLWE, err := cc.GetBinCCForSchemeSwitch()
	if err != nil {
		return fmt.Errorf("GetBinCCForSchemeSwitch: %w", err)
	}

	// Generate switching keys
	if err := cc.EvalCKKStoFHEWKeyGen(keys, lwesk); err != nil {
		return fmt.Errorf("EvalCKKStoFHEWKeyGen: %w", err)
	}

	// Get FHEW parameters
	pLWE, err := ccLWE.GetMaxPlaintextSpace()
	if err != nil {
		return fmt.Errorf("GetMaxPlaintextSpace: %w", err)
	}

	n, err := ccLWE.Getn()
	if err != nil {
		return fmt.Errorf("Getn: %w", err)
	}

	q, err := ccLWE.Getq()
	if err != nil {
		return fmt.Errorf("Getq: %w", err)
	}

	fmt.Printf("  FHEW lattice parameter n: %d\n", n)
	fmt.Printf("  FHEW ciphertext modulus q: %d\n", q)
	fmt.Printf("  FHEW plaintext modulus p: %d\n\n", pLWE)

	fmt.Println("Step 4: Encrypting data in CKKS")

	// Input data - small integers that fit in FHEW plaintext space
	x := []float64{0.0, 1.0, 2.0, 3.0, 0.0, 1.0, 2.0, 3.0}
	fmt.Printf("  Input: %v\n", x)

	ptxt, err := cc.MakeCKKSPackedPlaintext(x)
	if err != nil {
		return fmt.Errorf("MakeCKKSPackedPlaintext: %w", err)
	}
	defer ptxt.Close()

	ckksCt, err := cc.Encrypt(keys, ptxt)
	if err != nil {
		return fmt.Errorf("Encrypt: %w", err)
	}
	defer ckksCt.Close()

	fmt.Println("Step 5: Switching from CKKS to FHEW")

	// Precompute scaling factor
	scale := 1.0 / float64(pLWE)
	if err := cc.EvalCKKStoFHEWPrecompute(scale); err != nil {
		return fmt.Errorf("EvalCKKStoFHEWPrecompute: %w", err)
	}

	// Perform the switch
	lweCts, err := cc.EvalCKKStoFHEW(ckksCt, uint32(len(x)))
	if err != nil {
		return fmt.Errorf("EvalCKKStoFHEW: %w", err)
	}
	defer func() {
		for _, ct := range lweCts {
			ct.Close()
		}
	}()

	fmt.Printf("  Converted %d CKKS values to FHEW ciphertexts\n\n", len(lweCts))

	fmt.Println("Step 6: Verifying results")
	fmt.Println("  Decrypting FHEW ciphertexts:")

	allCorrect := true
	for i := 0; i < len(lweCts) && i < len(x); i++ {
		result, err := lwesk.DecryptLWECiphertext(ccLWE, lweCts[i], uint64(pLWE))
		if err != nil {
			fmt.Printf("    [%d] Error decrypting: %v\n", i, err)
			allCorrect = false
			continue
		}

		// Compute expected value matching C++ test pattern
		// C++ does: static_cast<int32_t>(static_cast<int32_t>(round(x)) % pLWE)
		rounded := int64(math.Round(x[i]))
		expected := rounded % int64(pLWE)
		if expected < 0 {
			expected += int64(pLWE)
		}
		status := "✓"
		if result != expected {
			status = "✗"
			allCorrect = false
		}
		fmt.Printf("    [%d] Got %d, Expected %d %s\n", i, result, expected, status)
	}

	if !allCorrect {
		return fmt.Errorf("some values were incorrect")
	}

	fmt.Println("\n  All values correct!")

	return nil
}
