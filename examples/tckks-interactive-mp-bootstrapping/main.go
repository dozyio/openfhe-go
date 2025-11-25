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

// Party represents a party in the TCKKS interactive bootstrapping protocol
type Party struct {
	ID         int
	SharesPair []*openfhe.Ciphertext // [h0, h1] = [masked decryption share, re-encryption share]
	KpShard    *openfhe.KeyPair      // Key-pair shard (pk, sk_i)
	PrivateKey *openfhe.PrivateKey
	PublicKey  *openfhe.PublicKey
}

func main() {
	fmt.Println("=== TCKKS Interactive Multi-Party Bootstrapping (3-Party) ===\n")

	// A. Setup parameters
	fmt.Println("1. Setting up CKKS parameters...")
	params, err := openfhe.NewParamsCKKSRNS()
	must(err, "NewParamsCKKSRNS")
	defer params.Close()

	// A1) Secret key distribution - use UNIFORM_TERNARY for CKKS multiparty
	must(params.SetSecretKeyDist(openfhe.SecretKeyUniformTernary), "SetSecretKeyDist")

	// A2) Security level
	must(params.SetSecurityLevel(openfhe.HEStd128Classic), "SetSecurityLevel")

	// A3) Scaling parameters
	dcrtBits := 50
	firstMod := 60
	must(params.SetScalingModSize(dcrtBits), "SetScalingModSize")
	must(params.SetScalingTechnique(openfhe.FLEXIBLEAUTO), "SetScalingTechnique")
	must(params.SetFirstModSize(firstMod), "SetFirstModSize")

	// A4) Multiplicative depth
	// Formula: multDepth >= desired_depth + interactive_bootstrapping_depth
	// Interactive bootstrapping depth is 3 for COMPACT, 4 for SLACK
	multiplicativeDepth := 7
	must(params.SetMultiplicativeDepth(multiplicativeDepth), "SetMultiplicativeDepth")
	must(params.SetKeySwitchTechnique(openfhe.HYBRID), "SetKeySwitchTechnique")

	batchSize := 4
	must(params.SetBatchSize(batchSize), "SetBatchSize")

	// Protocol-specific parameters: SLACK is more secure, COMPACT is more efficient
	// SLACK: Larger masks, more secure (default)
	// COMPACT: Smaller masks, more efficient
	must(params.SetInteractiveBootCompressionLevel(openfhe.SLACK), "SetInteractiveBootCompressionLevel")

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

	numParties := 3
	fmt.Printf("\n3. Interactive Multi-Party Bootstrapping Protocol Parameters:\n")
	fmt.Printf("   Number of parties: %d\n", numParties)
	fmt.Printf("   Compression level: SLACK (more secure, larger masks)\n")

	// C. Key Generation
	fmt.Println("\n4. Performing multi-party key generation...")
	parties := make([]Party, numParties)

	// Initialize parties and generate key shards
	for i := 0; i < numParties; i++ {
		parties[i].ID = i
		fmt.Printf("   Party %d: Generating key shard...\n", i)

		if i == 0 {
			// Party 0 is the leading party - generates initial keypair
			parties[i].KpShard, err = cc.KeyGen()
			must(err, "KeyGen party 0")
		} else {
			// Other parties generate keypairs from previous party's public key
			prevPK := parties[i-1].PublicKey
			parties[i].KpShard, err = cc.MultipartyKeyGenFromPublicKey(prevPK, false, false)
			must(err, "MultipartyKeyGen party "+fmt.Sprint(i))
		}

		// Extract private and public keys
		parties[i].PrivateKey, err = parties[i].KpShard.GetMultipartyPrivateKey()
		must(err, "GetMultipartyPrivateKey party "+fmt.Sprint(i))

		parties[i].PublicKey, err = parties[i].KpShard.GetMultipartyPublicKey()
		must(err, "GetMultipartyPublicKey party "+fmt.Sprint(i))

		fmt.Printf("   Party %d: Key generation completed\n", i)
	}

	// Generate collective public key from all secret keys
	fmt.Println("   Generating joint public key...")
	secretKeys := make([]*openfhe.PrivateKey, numParties)
	for i := 0; i < numParties; i++ {
		secretKeys[i] = parties[i].PrivateKey
	}
	kpMultiparty, err := cc.MultipartyKeyGen(secretKeys)
	must(err, "MultipartyKeyGen collective")
	defer kpMultiparty.Close()

	jointPK, err := kpMultiparty.GetMultipartyPublicKey()
	must(err, "GetMultipartyPublicKey joint")
	defer jointPK.Close()

	fmt.Println("   Joint public key generated successfully")

	// D. Prepare input and encrypt
	fmt.Println("\n5. Preparing plaintext and encrypting...")
	msg := []complex128{
		complex(-0.9, 0), complex(-0.8, 0),
		complex(0.2, 0), complex(0.4, 0),
	}

	ptxt, err := cc.MakeCKKSComplexPackedPlaintext(msg)
	must(err, "MakeCKKSComplexPackedPlaintext")
	defer ptxt.Close()

	fmt.Printf("   Original plaintext: %v\n", msg)

	// Encrypt with joint public key
	inCtxt, err := cc.Encrypt(kpMultiparty, ptxt)
	must(err, "Encrypt")
	defer inCtxt.Close()

	fmt.Println("   Encryption successful")

	// E. INTERACTIVE BOOTSTRAPPING PROTOCOL
	fmt.Println("\n=== INTERACTIVE BOOTSTRAPPING STARTS ===")

	// Step 1: Compress ciphertext to smallest number of towers
	fmt.Println("Step 1: Adjusting scale (compressing to minimum towers)...")
	inCtxt, err = cc.IntMPBootAdjustScale(inCtxt)
	must(err, "IntMPBootAdjustScale")
	fmt.Println("   Scale adjustment completed")

	// Step 2: Leading party generates Common Random Polynomial (CRP)
	fmt.Println("Step 2: Party 0 (lead) generating Common Random Poly (a)...")
	a, err := cc.IntMPBootRandomElementGen(parties[0].PublicKey)
	must(err, "IntMPBootRandomElementGen")
	defer a.Close()
	fmt.Println("   Common Random Poly generated")

	// Step 3: Each party generates its shares
	fmt.Println("Step 3: Each party generating masked decryption and re-encryption shares...")

	// Extract c1 from ciphertext (remove c0, keep only c1)
	c1, err := inCtxt.Clone()
	must(err, "Clone ciphertext")
	defer c1.Close()

	// Remove first element to get c1 only
	err = c1.SetElementAtIndex(1)
	must(err, "SetElementAtIndex")

	sharesPairVec := make([][]*openfhe.Ciphertext, numParties)
	for i := 0; i < numParties; i++ {
		fmt.Printf("   Party %d: Computing shares...\n", i)
		sharesPair, err := cc.IntMPBootDecrypt(parties[i].PrivateKey, c1, a)
		must(err, "IntMPBootDecrypt party "+fmt.Sprint(i))

		parties[i].SharesPair = sharesPair
		sharesPairVec[i] = sharesPair
		fmt.Printf("   Party %d: Shares generated\n", i)
	}

	// Step 4: Aggregate all shares
	fmt.Println("Step 4: Aggregating shares from all parties...")
	aggregatedSharesPair, err := cc.IntMPBootAdd(sharesPairVec)
	must(err, "IntMPBootAdd")
	defer aggregatedSharesPair[0].Close()
	defer aggregatedSharesPair[1].Close()
	fmt.Println("   Shares aggregated successfully")

	// Step 5: Leading party finalizes protocol by re-encrypting
	fmt.Println("Step 5: Party 0 (lead) finalizing protocol (re-encryption)...")
	outCtxt, err := cc.IntMPBootEncrypt(parties[0].PublicKey, aggregatedSharesPair, a, inCtxt)
	must(err, "IntMPBootEncrypt")
	defer outCtxt.Close()
	fmt.Println("   Re-encryption completed")

	fmt.Println("\n=== INTERACTIVE BOOTSTRAPPING ENDED ===")

	// F. Distributed Decryption
	fmt.Println("\n6. Performing distributed decryption...")

	partialCiphertextVec := make([]*openfhe.Ciphertext, 0, numParties)

	// Party 0 (lead) performs lead decryption
	fmt.Println("   Party 0 (lead): Performing lead decryption...")
	partial0, err := cc.MultipartyDecryptLead([]*openfhe.Ciphertext{outCtxt}, parties[0].PrivateKey)
	must(err, "MultipartyDecryptLead")
	defer partial0[0].Close()
	partialCiphertextVec = append(partialCiphertextVec, partial0[0])

	// Other parties perform main decryption
	for i := 1; i < numParties; i++ {
		fmt.Printf("   Party %d: Performing partial decryption...\n", i)
		partial, err := cc.MultipartyDecryptMain([]*openfhe.Ciphertext{outCtxt}, parties[i].PrivateKey)
		must(err, "MultipartyDecryptMain party "+fmt.Sprint(i))
		defer partial[0].Close()
		partialCiphertextVec = append(partialCiphertextVec, partial[0])
	}

	// Fuse partial decryptions
	fmt.Println("   Fusing partial decryptions...")
	plaintextMultiparty, err := cc.MultipartyDecryptFusion(partialCiphertextVec)
	must(err, "MultipartyDecryptFusion")
	defer plaintextMultiparty.Close()

	must(plaintextMultiparty.SetLength(len(msg)), "SetLength")

	// G. Verify results
	fmt.Println("\n7. Verifying results...")
	result, err := plaintextMultiparty.GetComplexPackedValue()
	must(err, "GetComplexPackedValue")

	fmt.Println("\nComparison:")
	fmt.Printf("   Original plaintext:      %v\n", msg)
	fmt.Printf("   After bootstrapping:     %v\n", result[:len(msg)])

	// Check approximate equality
	if approxEqualComplex(result[:len(msg)], msg, 0.01) {
		fmt.Println("\n✓ SUCCESS! TCKKS Interactive Multi-Party Bootstrapping completed successfully!")
		fmt.Println("  All three parties jointly bootstrapped and decrypted the ciphertext.")
		fmt.Println("  Bootstrapped values match the original plaintext within tolerance.")
	} else {
		fmt.Println("\n✗ WARNING: Bootstrapped values differ from input beyond tolerance")
		for i := 0; i < len(msg); i++ {
			diff := cmplx.Abs(result[i] - msg[i])
			fmt.Printf("  [%d] diff: %.6f\n", i, diff)
		}
	}

	// Cleanup party resources
	for i := 0; i < numParties; i++ {
		if parties[i].PrivateKey != nil {
			parties[i].PrivateKey.Close()
		}
		if parties[i].PublicKey != nil {
			parties[i].PublicKey.Close()
		}
		if parties[i].SharesPair != nil {
			for _, share := range parties[i].SharesPair {
				if share != nil {
					share.Close()
				}
			}
		}
	}

	fmt.Println("\n=== TCKKS Interactive Multi-Party Bootstrapping Example Completed ===")
}
