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

func main() {
	fmt.Println("--- Go interactive-bootstrapping (Threshold FHE) ---")

	// === 1) Setup parameters ===
	params, err := openfhe.NewParamsCKKSRNS()
	must(err, "NewParamsCKKSRNS")
	defer params.Close()

	// 1 extra level needs to be added for FIXED* modes (2 extra levels for FLEXIBLE* modes)
	// to support 2-party interactive bootstrapping
	depth := uint32(7)
	must(params.SetMultiplicativeDepth(int(depth)), "SetMultiplicativeDepth")
	must(params.SetScalingModSize(50), "SetScalingModSize")
	must(params.SetBatchSize(16), "SetBatchSize")
	must(params.SetScalingTechnique(openfhe.FLEXIBLEAUTO), "SetScalingTechnique")

	// === 2) Create crypto context ===
	cc, err := openfhe.NewCryptoContextCKKS(params)
	must(err, "NewCryptoContextCKKS")
	defer cc.Close()

	// Enable features
	must(cc.Enable(openfhe.PKE), "Enable PKE")
	must(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")
	must(cc.Enable(openfhe.ADVANCEDSHE), "Enable ADVANCEDSHE")
	must(cc.Enable(openfhe.MULTIPARTY), "Enable MULTIPARTY")

	// === 3) Key Generation - Round 1 (Party A) ===
	fmt.Println("\nRunning key generation (used for source data)...")
	fmt.Println("Round 1 (party A) started.")

	kp1, err := cc.KeyGen()
	must(err, "KeyGen party 1")
	defer kp1.Close()

	// Extract private/public keys for multiparty operations
	sk1, err := kp1.GetMultipartyPrivateKey()
	must(err, "GetMultipartyPrivateKey party 1")
	defer sk1.Close()

	pk1, err := kp1.GetMultipartyPublicKey()
	must(err, "GetMultipartyPublicKey party 1")
	defer pk1.Close()

	// Generate evalmult key part for A
	evalMultKey, err := cc.KeySwitchGen(sk1, sk1)
	must(err, "KeySwitchGen party 1")
	defer evalMultKey.Close()

	fmt.Println("Round 1 of key generation completed.")

	// === 4) Key Generation - Round 2 (Party B) ===
	fmt.Println("Round 2 (party B) started.")
	fmt.Println("Joint public key for (s_a + s_b) is generated...")

	kp2, err := cc.MultipartyKeyGenFromPublicKey(pk1, false, true)
	must(err, "MultipartyKeyGen party 2")
	defer kp2.Close()

	pk2, err := kp2.GetMultipartyPublicKey()
	must(err, "GetMultipartyPublicKey party 2")
	defer pk2.Close()

	sk2, err := kp2.GetMultipartyPrivateKey()
	must(err, "GetMultipartyPrivateKey party 2")
	defer sk2.Close()

	// === 5) Create and encrypt plaintext ===
	input := []complex128{
		complex(-0.9, 0), complex(-0.8, 0), complex(-0.6, 0),
		complex(-0.4, 0), complex(-0.2, 0), complex(0.0, 0),
		complex(0.2, 0), complex(0.4, 0), complex(0.6, 0),
		complex(0.8, 0), complex(0.9, 0),
	}

	// This plaintext only has 3 RNS limbs, the minimum needed to perform 2-party
	// interactive bootstrapping for FLEXIBLEAUTO
	// Parameters: (data, scaleDeg=1, level=depth-2) - matches C++ signature exactly
	plaintext1, err := cc.MakeCKKSComplexPackedPlaintextWithParams(input, 1.0, int(depth-2))
	must(err, "MakeCKKSComplexPackedPlaintextWithParams")
	defer plaintext1.Close()

	ciphertext1, err := cc.Encrypt(kp2, plaintext1)
	must(err, "Encrypt")
	defer ciphertext1.Close()

	// === 6) INTERACTIVE BOOTSTRAPPING STARTS ===
	fmt.Println("\nStarting interactive bootstrapping protocol...")

	// Step 1: Adjust scale - reduces to two towers (RNS limbs)
	ciphertext1, err = cc.IntBootAdjustScale(ciphertext1)
	must(err, "IntBootAdjustScale")
	fmt.Println("IntBootAdjustScale Succeeded")

	// Step 2: Masked decryption on the server: c0 = b + a*s0
	ciphertextOutput1, err := cc.IntBootDecrypt(sk1, ciphertext1)
	must(err, "IntBootDecrypt on Server")
	defer ciphertextOutput1.Close()
	fmt.Println("IntBootDecrypt on Server Succeeded")

	// Step 3: Clone ciphertext and extract just the second element for client
	// This matches the C++ version: ciphertext2->SetElements({ciphertext2->GetElements()[1]})
	ciphertext2, err := ciphertext1.Clone()
	must(err, "Clone ciphertext")
	defer ciphertext2.Close()

	// Keep only the second element (index 1): c1 = a (the 'a' part of the ciphertext)
	err = ciphertext2.SetElementAtIndex(1)
	must(err, "SetElementAtIndex")

	// Step 4: Masked decryption on the client: c1 = a*s1
	ciphertextOutput2, err := cc.IntBootDecrypt(sk2, ciphertext2)
	must(err, "IntBootDecrypt on Client")
	defer ciphertextOutput2.Close()
	fmt.Println("IntBootDecrypt on Client Succeeded")

	// Step 5: Encryption of masked decryption c1 = a*s1
	ciphertextOutput2, err = cc.IntBootEncrypt(pk2, ciphertextOutput2)
	must(err, "IntBootEncrypt on Client")
	fmt.Println("IntBootEncrypt on Client Succeeded")

	// Step 6: Compute Enc(c1) + c0
	ciphertextOutput, err := cc.IntBootAdd(ciphertextOutput2, ciphertextOutput1)
	must(err, "IntBootAdd on Server")
	defer ciphertextOutput.Close()
	fmt.Println("IntBootAdd on Server Succeeded")

	// === 7) INTERACTIVE BOOTSTRAPPING ENDS ===
	fmt.Println("Interactive bootstrapping protocol completed.\n")

	// === 8) Distributed decryption ===
	fmt.Println("Performing distributed decryption...")

	ciphertextPartial1, err := cc.MultipartyDecryptLead([]*openfhe.Ciphertext{ciphertextOutput}, sk1)
	must(err, "MultipartyDecryptLead")
	defer ciphertextPartial1[0].Close()

	ciphertextPartial2, err := cc.MultipartyDecryptMain([]*openfhe.Ciphertext{ciphertextOutput}, sk2)
	must(err, "MultipartyDecryptMain")
	defer ciphertextPartial2[0].Close()

	partialCiphertextVec := []*openfhe.Ciphertext{
		ciphertextPartial1[0],
		ciphertextPartial2[0],
	}

	plaintextMultiparty, err := cc.MultipartyDecryptFusion(partialCiphertextVec)
	must(err, "MultipartyDecryptFusion")
	defer plaintextMultiparty.Close()

	must(plaintextMultiparty.SetLength(len(input)), "SetLength")

	// === 9) Compare results ===
	got, err := plaintextMultiparty.GetComplexPackedValue()
	must(err, "GetComplexPackedValue")

	fmt.Println("Original plaintext:")
	for i := 0; i < len(input); i++ {
		fmt.Printf("  [%d] %v\n", i, input[i])
	}

	fmt.Println("\nResult after bootstrapping:")
	for i := 0; i < len(input) && i < len(got); i++ {
		fmt.Printf("  [%d] %v (expected %v, diff %.6f)\n",
			i, got[i], input[i], cmplx.Abs(got[i]-input[i]))
	}

	// Check if results are approximately equal
	if approxEqualComplex(got[:len(input)], input, 0.01) {
		fmt.Println("\n✓ Interactive bootstrapping successful (values match input within tolerance)")
	} else {
		fmt.Println("\n✗ Warning: Interactive bootstrapping result differs from input")
	}
}
