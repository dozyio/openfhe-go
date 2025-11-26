package main

import (
	"fmt"
	"log"
	"math/cmplx"

	"github.com/dozyio/openfhe-go/openfhe"
)

func must(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}

func approxEqualComplex(a, b []complex128, tol float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if cmplx.Abs(a[i]-b[i]) > tol {
			return false
		}
	}
	return true
}

// runTCKKSCollectiveBoot demonstrates TCKKS interactive bootstrapping with Chebyshev evaluation
// This follows Protocol 5 from "Multiparty Homomorphic Encryption from Ring-Learning-With-Errors"
// https://eprint.iacr.org/2020/304
func runTCKKSCollectiveBoot(scalingTechnique int) {
	scalingTechniqueName := ""
	switch scalingTechnique {
	case openfhe.FIXEDMANUAL:
		scalingTechniqueName = "FIXEDMANUAL"
	case openfhe.FIXEDAUTO:
		scalingTechniqueName = "FIXEDAUTO"
	case openfhe.FLEXIBLEAUTO:
		scalingTechniqueName = "FLEXIBLEAUTO"
	case openfhe.FLEXIBLEAUTOEXT:
		scalingTechniqueName = "FLEXIBLEAUTOEXT"
	}
	fmt.Printf("\n=== TCKKS Interactive Bootstrapping with Chebyshev Series (%s) ===\n", scalingTechniqueName)

	// A. Setup parameters
	fmt.Println("\n1. Setting up CKKS parameters...")
	params, err := openfhe.NewParamsCKKSRNS()
	must(err, "NewParamsCKKSRNS")
	defer params.Close()

	// A1) Secret key distribution - UNIFORM_TERNARY for CKKS multiparty
	must(params.SetSecretKeyDist(openfhe.SecretKeyUniformTernary), "SetSecretKeyDist")

	// A2) Security level
	must(params.SetSecurityLevel(openfhe.HEStd128Classic), "SetSecurityLevel")

	// A3) Scaling parameters
	dcrtBits := 50
	firstMod := 60
	must(params.SetScalingModSize(dcrtBits), "SetScalingModSize")
	must(params.SetScalingTechnique(scalingTechnique), "SetScalingTechnique")
	must(params.SetFirstModSize(firstMod), "SetFirstModSize")

	// A4) Multiplicative depth
	// Need depth for Chebyshev series (uses several levels) + interactive bootstrapping
	// COMPACT requires 3 levels for bootstrapping, SLACK requires 4
	multiplicativeDepth := 10
	must(params.SetMultiplicativeDepth(multiplicativeDepth), "SetMultiplicativeDepth")
	must(params.SetKeySwitchTechnique(openfhe.HYBRID), "SetKeySwitchTechnique")

	batchSize := 16
	must(params.SetBatchSize(batchSize), "SetBatchSize")

	// Use COMPACT compression (more efficient, requires 3 levels for bootstrapping)
	// COMPACT uses smaller masks and is more efficient than SLACK
	must(params.SetInteractiveBootCompressionLevel(openfhe.COMPACT), "SetInteractiveBootCompressionLevel")

	// B. Generate crypto context
	fmt.Println("2. Generating crypto context...")
	cc, err := openfhe.NewCryptoContextCKKS(params)
	must(err, "NewCryptoContextCKKS")
	defer cc.Close()

	// Enable features
	must(cc.Enable(openfhe.PKE), "Enable PKE")
	must(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	must(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")
	must(cc.Enable(openfhe.ADVANCEDSHE), "Enable ADVANCEDSHE")
	must(cc.Enable(openfhe.MULTIPARTY), "Enable MULTIPARTY")

	ringDim := cc.GetRingDimension()
	maxNumSlots := ringDim / 2
	fmt.Printf("   Ring dimension: %d\n", ringDim)
	fmt.Printf("   Batch size: %d\n", batchSize)
	fmt.Printf("   Max slots: %d\n", maxNumSlots)
	fmt.Printf("   Scaling technique: %s\n", scalingTechniqueName)

	numParties := 3
	fmt.Printf("\n3. TCKKS Protocol Parameters:\n")
	fmt.Printf("   Number of parties: %d\n", numParties)
	fmt.Printf("   Compression level: COMPACT (more efficient, smaller masks)\n")

	// C. Multi-party Key Generation (following Protocol 5 from the research paper)
	fmt.Println("\n4. Performing multi-party key generation...")

	// Initialize keypairs for the 3 parties
	var kp1, kp2, kp3 *openfhe.KeyPair

	////////////////////////////////////////////////////////////
	// Round 1 (Party A / kp1)
	////////////////////////////////////////////////////////////
	fmt.Println("   Round 1 - Party 1 (A): Initial key generation...")
	kp1, err = cc.KeyGen()
	must(err, "KeyGen party 1")
	defer kp1.Close()

	sk1, err := kp1.SecretKey()
	must(err, "Get secret key party 1")
	defer sk1.Close()

	pk1, err := kp1.PublicKey()
	must(err, "Get public key party 1")
	defer pk1.Close()

	// Generate eval mult key part for Party 1
	fmt.Println("   Party 1: Generating eval mult key...")
	evalMultKey, err := cc.KeySwitchGen(sk1, sk1)
	must(err, "KeySwitchGen party 1")
	defer evalMultKey.Close()

	// Generate eval sum key part for Party 1
	fmt.Println("   Party 1: Generating eval sum key...")
	must(cc.EvalSumKeyGenPrivate(sk1, nil), "EvalSumKeyGen party 1")

	keyTag1, err := sk1.GetKeyTag()
	must(err, "GetKeyTag party 1")

	evalSumKeys, err := cc.GetEvalSumKeyMap(keyTag1)
	must(err, "GetEvalSumKeyMap party 1")
	defer evalSumKeys.Close()

	////////////////////////////////////////////////////////////
	// Round 2 (Party B / kp2)
	////////////////////////////////////////////////////////////
	fmt.Println("   Round 2 - Party 2 (B): Multiparty key generation...")
	kp2, err = cc.MultipartyKeyGenFromPublicKey(pk1, false, false)
	must(err, "MultipartyKeyGen party 2")
	defer kp2.Close()

	sk2, err := kp2.SecretKey()
	must(err, "Get secret key party 2")
	defer sk2.Close()

	pk2, err := kp2.PublicKey()
	must(err, "Get public key party 2")
	defer pk2.Close()

	keyTag2, err := pk2.GetKeyTag()
	must(err, "GetKeyTag party 2")

	// Generate and combine eval mult keys
	fmt.Println("   Party 2: Generating and combining eval mult keys...")
	evalMultKey2, err := cc.MultiKeySwitchGen(sk2, sk2, evalMultKey)
	must(err, "MultiKeySwitchGen party 2")
	defer evalMultKey2.Close()

	evalMultAB, err := cc.MultiAddEvalKeys(evalMultKey, evalMultKey2, keyTag2)
	must(err, "MultiAddEvalKeys AB")
	defer evalMultAB.Close()

	evalMultBAB, err := cc.MultiMultEvalKey(sk2, evalMultAB, keyTag2)
	must(err, "MultiMultEvalKey BAB")
	defer evalMultBAB.Close()

	evalMultAAB, err := cc.MultiMultEvalKey(sk1, evalMultAB, keyTag2)
	must(err, "MultiMultEvalKey AAB")
	defer evalMultAAB.Close()

	evalMultKeyTagAB, err := evalMultAB.GetKeyTag()
	must(err, "GetKeyTag evalMultAB")

	evalMultFinal, err := cc.MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultKeyTagAB)
	must(err, "MultiAddEvalMultKeys final AB")
	defer evalMultFinal.Close()

	must(cc.InsertEvalMultKey([]*openfhe.EvalKey{evalMultFinal}), "InsertEvalMultKey AB")

	// Generate and combine eval sum keys
	fmt.Println("   Party 2: Generating and combining eval sum keys...")
	evalSumKeysB, err := cc.MultiEvalSumKeyGen(sk2, evalSumKeys, keyTag2)
	must(err, "MultiEvalSumKeyGen party 2")
	defer evalSumKeysB.Close()

	evalSumKeysJoin, err := cc.MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, keyTag2)
	must(err, "MultiAddEvalSumKeys join")
	defer evalSumKeysJoin.Close()

	must(cc.InsertEvalSumKey(evalSumKeysJoin), "InsertEvalSumKey join")

	////////////////////////////////////////////////////////////
	// Round 3 (Party C / kp3) - Lead party
	////////////////////////////////////////////////////////////
	fmt.Println("   Round 3 - Party 3 (C / Lead): Multiparty key generation...")
	kp3, err = cc.MultipartyKeyGenFromPublicKey(pk2, false, false)
	must(err, "MultipartyKeyGen party 3")
	defer kp3.Close()

	sk3, err := kp3.SecretKey()
	must(err, "Get secret key party 3")
	defer sk3.Close()

	pk3, err := kp3.PublicKey()
	must(err, "Get public key party 3")
	defer pk3.Close()

	keyTag3, err := pk3.GetKeyTag()
	must(err, "GetKeyTag party 3")

	// Generate and combine eval mult keys for all 3 parties
	fmt.Println("   Party 3: Generating and combining eval mult keys for all parties...")
	evalMultKey3, err := cc.MultiKeySwitchGen(sk3, sk3, evalMultKey)
	must(err, "MultiKeySwitchGen party 3")
	defer evalMultKey3.Close()

	evalMultABC, err := cc.MultiAddEvalKeys(evalMultAB, evalMultKey3, keyTag3)
	must(err, "MultiAddEvalKeys ABC")
	defer evalMultABC.Close()

	evalMultBABC, err := cc.MultiMultEvalKey(sk2, evalMultABC, keyTag3)
	must(err, "MultiMultEvalKey BABC")
	defer evalMultBABC.Close()

	evalMultAABC, err := cc.MultiMultEvalKey(sk1, evalMultABC, keyTag3)
	must(err, "MultiMultEvalKey AABC")
	defer evalMultAABC.Close()

	evalMultCABC, err := cc.MultiMultEvalKey(sk3, evalMultABC, keyTag3)
	must(err, "MultiMultEvalKey CABC")
	defer evalMultCABC.Close()

	evalMultKeyTagBABC, err := evalMultBABC.GetKeyTag()
	must(err, "GetKeyTag evalMultBABC")

	evalMultABABC, err := cc.MultiAddEvalMultKeys(evalMultBABC, evalMultAABC, evalMultKeyTagBABC)
	must(err, "MultiAddEvalMultKeys ABABC")
	defer evalMultABABC.Close()

	evalMultKeyTagCABC, err := evalMultCABC.GetKeyTag()
	must(err, "GetKeyTag evalMultCABC")

	evalMultFinal2, err := cc.MultiAddEvalMultKeys(evalMultABABC, evalMultCABC, evalMultKeyTagCABC)
	must(err, "MultiAddEvalMultKeys final ABC")
	defer evalMultFinal2.Close()

	must(cc.InsertEvalMultKey([]*openfhe.EvalKey{evalMultFinal2}), "InsertEvalMultKey ABC")

	// Generate and combine eval sum keys for all 3 parties
	fmt.Println("   Party 3: Generating and combining eval sum keys for all parties...")
	evalSumKeysC, err := cc.MultiEvalSumKeyGen(sk3, evalSumKeys, keyTag3)
	must(err, "MultiEvalSumKeyGen party 3")
	defer evalSumKeysC.Close()

	evalSumKeysJoin2, err := cc.MultiAddEvalSumKeys(evalSumKeysJoin, evalSumKeysC, keyTag3)
	must(err, "MultiAddEvalSumKeys join2")
	defer evalSumKeysJoin2.Close()

	must(cc.InsertEvalSumKey(evalSumKeysJoin2), "InsertEvalSumKey join2")

	fmt.Println("   Multi-party key generation completed successfully")

	// D. Prepare input and encrypt
	fmt.Println("\n5. Preparing input and evaluating Chebyshev series...")
	input := []complex128{
		complex(-4.0, 0), complex(-3.0, 0), complex(-2.0, 0),
		complex(-1.0, 0), complex(0.0, 0), complex(1.0, 0),
		complex(2.0, 0), complex(3.0, 0), complex(4.0, 0),
	}
	encodedLength := len(input)

	ptxt, err := cc.MakeCKKSComplexPackedPlaintext(input)
	must(err, "MakeCKKSComplexPackedPlaintext")
	defer ptxt.Close()

	fmt.Printf("   Input plaintext: %v\n", input)

	// Encrypt with party 3's keypair (lead party)
	ct1, err := cc.Encrypt(kp3, ptxt)
	must(err, "Encrypt")
	defer ct1.Close()

	// Chebyshev coefficients for sigmoid-like function approximation
	// This approximates the sigmoid function over the range [-4, 4]
	coefficients := []float64{
		1.0, 0.558971, 0.0, -0.0943712, 0.0, 0.0215023, 0.0, -0.00505348, 0.0, 0.00119324,
		0.0, -0.000281928, 0.0, 0.0000664347, 0.0, -0.0000148709,
	}
	// Input range for Chebyshev approximation
	a := -4.0
	b := 4.0

	// Evaluate Chebyshev series on encrypted data
	fmt.Println("   Evaluating Chebyshev series on encrypted data...")
	ct1, err = cc.EvalChebyshevSeries(ct1, coefficients, a, b)
	must(err, "EvalChebyshevSeries")
	fmt.Println("   Chebyshev series evaluation completed")

	// E. INTERACTIVE BOOTSTRAPPING PROTOCOL
	fmt.Println("\n=== INTERACTIVE BOOTSTRAPPING STARTS ===")

	// Step 1: Compress ciphertext to smallest number of towers
	ct1, err = cc.IntMPBootAdjustScale(ct1)
	must(err, "IntMPBootAdjustScale")

	// Step 2: Leading party (Party 3) generates Common Random Polynomial (CRP)
	// a is sampled at random uniformly from R_{Q}
	crp, err := cc.IntMPBootRandomElementGen(pk3)
	must(err, "IntMPBootRandomElementGen")
	defer crp.Close()

	// Step 3: Each party generates its own shares: maskedDecryptionShare and reEncryptionShare
	// (h_{0,i}, h_{1,i}) = (masked decryption share, re-encryption share)

	// Extract c1 - element-wise (remove c0, keep c1 and any higher-degree terms)
	c1, err := ct1.Clone()
	must(err, "Clone ciphertext")
	defer c1.Close()
	err = c1.EraseFirstElement() // Equivalent to C++ c1->GetElements().erase(c1->GetElements().begin())
	must(err, "EraseFirstElement")

	// Masked decryption on the client: c1 = a*s1
	sharesPair0, err := cc.IntMPBootDecrypt(sk1, c1, crp)
	must(err, "IntMPBootDecrypt party 1")
	defer sharesPair0[0].Close()
	defer sharesPair0[1].Close()

	sharesPair1, err := cc.IntMPBootDecrypt(sk2, c1, crp)
	must(err, "IntMPBootDecrypt party 2")
	defer sharesPair1[0].Close()
	defer sharesPair1[1].Close()

	sharesPair2, err := cc.IntMPBootDecrypt(sk3, c1, crp)
	must(err, "IntMPBootDecrypt party 3")
	defer sharesPair2[0].Close()
	defer sharesPair2[1].Close()

	sharesPairVec := [][]*openfhe.Ciphertext{sharesPair0, sharesPair1, sharesPair2}

	// Step 4: Party 3 finalizes the protocol by aggregating the shares and reEncrypting the results
	aggregatedSharesPair, err := cc.IntMPBootAdd(sharesPairVec)
	must(err, "IntMPBootAdd")
	defer aggregatedSharesPair[0].Close()
	defer aggregatedSharesPair[1].Close()

	ciphertextOutput, err := cc.IntMPBootEncrypt(pk3, aggregatedSharesPair, crp, ct1)
	must(err, "IntMPBootEncrypt")
	defer ciphertextOutput.Close()

	fmt.Println("\n=== INTERACTIVE BOOTSTRAPPING ENDED ===")

	// F. Distributed Decryption
	fmt.Println("\n6. Performing distributed decryption...")

	ciphertextPartial1, err := cc.MultipartyDecryptMain([]*openfhe.Ciphertext{ciphertextOutput}, sk1)
	must(err, "MultipartyDecryptMain party 1")
	defer ciphertextPartial1[0].Close()

	ciphertextPartial2, err := cc.MultipartyDecryptMain([]*openfhe.Ciphertext{ciphertextOutput}, sk2)
	must(err, "MultipartyDecryptMain party 2")
	defer ciphertextPartial2[0].Close()

	ciphertextPartial3, err := cc.MultipartyDecryptLead([]*openfhe.Ciphertext{ciphertextOutput}, sk3)
	must(err, "MultipartyDecryptLead")
	defer ciphertextPartial3[0].Close()

	partialCiphertextVec := []*openfhe.Ciphertext{
		ciphertextPartial1[0],
		ciphertextPartial2[0],
		ciphertextPartial3[0],
	}

	plaintextMultiparty, err := cc.MultipartyDecryptFusion(partialCiphertextVec)
	must(err, "MultipartyDecryptFusion")
	defer plaintextMultiparty.Close()

	must(plaintextMultiparty.SetLength(encodedLength), "SetLength")

	// G. Verify results
	fmt.Println("\n7. Verifying results...")
	result, err := plaintextMultiparty.GetComplexPackedValue()
	must(err, "GetComplexPackedValue")

	// Ground truth result - expected sigmoid approximation values for the input
	// These are the expected values after applying the Chebyshev approximation to the sigmoid
	groundTruth := []complex128{
		complex(0.0179885, 0), complex(0.0474289, 0), complex(0.119205, 0),
		complex(0.268936, 0), complex(0.5, 0), complex(0.731064, 0),
		complex(0.880795, 0), complex(0.952571, 0), complex(0.982011, 0),
	}

	fmt.Println("\nComparison:")
	fmt.Printf("   Input plaintext:      %v\n", input)
	fmt.Printf("   Ground Truth (sigmoid): %v\n", groundTruth)
	fmt.Printf("   Computed Result:      %v\n", result[:encodedLength])

	eps := 0.0001
	// Check approximate equality
	if approxEqualComplex(result[:encodedLength], groundTruth, eps) {
		fmt.Println("\n✓ SUCCESS! TCKKS Interactive Bootstrapping with Chebyshev completed successfully!")
		fmt.Println("  All three parties jointly evaluated Chebyshev series, bootstrapped, and decrypted.")
		fmt.Println("  Computed values match the ground truth within tolerance.")
	} else {
		fmt.Println("\n⚠ WARNING: Computed values differ from ground truth beyond tolerance")
		for i := 0; i < encodedLength; i++ {
			diff := cmplx.Abs(result[i] - groundTruth[i])
			fmt.Printf("  [%d] input: %.1f, expected: %.6f, got: %.6f, diff: %.6f\n",
				i, real(input[i]), real(groundTruth[i]), real(result[i]), diff)
		}
	}

	fmt.Printf("\n=== TCKKS Chebyshev Example with %s Completed ===\n", scalingTechniqueName)
}

func main() {
	fmt.Println("=== TCKKS Interactive Multi-Party Bootstrapping with Chebyshev Series ===\n")
	fmt.Println("This example demonstrates:")
	fmt.Println("  - Multi-party threshold CKKS (3 parties)")
	fmt.Println("  - Chebyshev series evaluation (sigmoid approximation)")
	fmt.Println("  - Interactive bootstrapping to refresh ciphertext")
	fmt.Println("  - Distributed decryption")
	fmt.Println()

	// Test with different scaling techniques
	// The C++ example tests all four, but some may be more suitable than others
	scalingTechniques := []struct {
		name  string
		value int
	}{
		{"FIXEDMANUAL", openfhe.FIXEDMANUAL},
		{"FIXEDAUTO", openfhe.FIXEDAUTO},
		{"FLEXIBLEAUTO", openfhe.FLEXIBLEAUTO},
		{"FLEXIBLEAUTOEXT", openfhe.FLEXIBLEAUTOEXT},
	}

	for _, st := range scalingTechniques {
		fmt.Printf("\n========================================")
		fmt.Printf("\nTesting with Scaling Technique: %s", st.name)
		fmt.Printf("\n========================================\n")
		runTCKKSCollectiveBoot(st.value)
	}

	fmt.Println("\n=== All TCKKS Interactive Bootstrapping Chebyshev Tests Completed ===")
}
