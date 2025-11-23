package main

import (
	"fmt"
	"log"

	"github.com/dozyio/openfhe-go/openfhe"
)

func main() {
	fmt.Println("=== OpenFHE Threshold FHE Example (3-Party BGV) ===\n")

	// Step 1: Setup crypto parameters
	fmt.Println("1. Setting up BGV parameters with NOISE_FLOODING_MULTIPARTY mode...")
	params, err := openfhe.NewParamsBGVrns()
	if err != nil {
		log.Fatal("NewParamsBGVrns:", err)
	}
	defer params.Close()

	if err := params.SetPlaintextModulus(65537); err != nil {
		log.Fatal("SetPlaintextModulus:", err)
	}

	if err := params.SetMultiplicativeDepth(2); err != nil {
		log.Fatal("SetMultiplicativeDepth:", err)
	}

	// Enable noise flooding for multiparty operations
	if err := params.SetMultipartyMode(openfhe.NOISE_FLOODING_MULTIPARTY); err != nil {
		log.Fatal("SetMultipartyMode:", err)
	}

	// Step 2: Generate crypto context
	fmt.Println("2. Generating crypto context...")
	cc, err := openfhe.NewCryptoContextBGV(params)
	if err != nil {
		log.Fatal("NewCryptoContextBGV:", err)
	}
	defer cc.Close()

	// Enable required features
	if err := cc.Enable(openfhe.PKE | openfhe.KEYSWITCH | openfhe.LEVELEDSHE | openfhe.ADVANCEDSHE | openfhe.MULTIPARTY); err != nil {
		log.Fatal("Enable:", err)
	}

	// Step 3: Generate keys for 3 parties
	fmt.Println("3. Generating keys for 3 parties...")

	// Party 1 generates initial keypair
	kp1, err := cc.KeyGen()
	if err != nil {
		log.Fatal("KeyGen party 1:", err)
	}
	defer kp1.Close()

	pk1, err := kp1.GetMultipartyPublicKey()
	if err != nil {
		log.Fatal("GetMultipartyPublicKey party 1:", err)
	}
	defer pk1.Close()
	fmt.Println("   Party 1: Keys generated")

	// Party 2 generates keypair from party 1's public key
	kp2, err := cc.MultipartyKeyGenFromPublicKey(pk1, false, false)
	if err != nil {
		log.Fatal("MultipartyKeyGen party 2:", err)
	}
	defer kp2.Close()

	pk2, err := kp2.GetMultipartyPublicKey()
	if err != nil {
		log.Fatal("GetMultipartyPublicKey party 2:", err)
	}
	defer pk2.Close()
	fmt.Println("   Party 2: Keys generated from Party 1's public key")

	// Party 3 generates keypair from party 2's public key (which includes party 1)
	kp3, err := cc.MultipartyKeyGenFromPublicKey(pk2, false, false)
	if err != nil {
		log.Fatal("MultipartyKeyGen party 3:", err)
	}
	defer kp3.Close()
	fmt.Println("   Party 3: Keys generated from Party 2's public key")

	// Step 4: Create plaintexts for each party
	fmt.Println("\n4. Creating plaintexts for each party...")
	values1 := []int64{10, 20, 30, 40, 50, 60, 70, 80}
	pt1, err := cc.MakePackedPlaintext(values1)
	if err != nil {
		log.Fatal("MakePackedPlaintext 1:", err)
	}
	defer pt1.Close()
	fmt.Printf("   Party 1 data: %v\n", values1)

	values2 := []int64{5, 10, 15, 20, 25, 30, 35, 40}
	pt2, err := cc.MakePackedPlaintext(values2)
	if err != nil {
		log.Fatal("MakePackedPlaintext 2:", err)
	}
	defer pt2.Close()
	fmt.Printf("   Party 2 data: %v\n", values2)

	values3 := []int64{1, 2, 3, 4, 5, 6, 7, 8}
	pt3, err := cc.MakePackedPlaintext(values3)
	if err != nil {
		log.Fatal("MakePackedPlaintext 3:", err)
	}
	defer pt3.Close()
	fmt.Printf("   Party 3 data: %v\n", values3)

	// Step 5: Encrypt with joint public key (party 3's key includes all parties)
	fmt.Println("\n5. Encrypting data with joint public key...")
	ct1, err := cc.Encrypt(kp3, pt1)
	if err != nil {
		log.Fatal("Encrypt 1:", err)
	}
	defer ct1.Close()

	ct2, err := cc.Encrypt(kp3, pt2)
	if err != nil {
		log.Fatal("Encrypt 2:", err)
	}
	defer ct2.Close()

	ct3, err := cc.Encrypt(kp3, pt3)
	if err != nil {
		log.Fatal("Encrypt 3:", err)
	}
	defer ct3.Close()
	fmt.Println("   All data encrypted")

	// Step 6: Perform homomorphic computation (addition)
	fmt.Println("\n6. Performing homomorphic addition: ct1 + ct2 + ct3...")
	ctAdd12, err := cc.EvalAdd(ct1, ct2)
	if err != nil {
		log.Fatal("EvalAdd 1+2:", err)
	}
	defer ctAdd12.Close()

	ctResult, err := cc.EvalAdd(ctAdd12, ct3)
	if err != nil {
		log.Fatal("EvalAdd result+3:", err)
	}
	defer ctResult.Close()
	fmt.Println("   Homomorphic computation complete")

	// Step 7: Multiparty decryption
	fmt.Println("\n7. Performing threshold decryption (requires all 3 parties)...")

	// Get private keys
	sk1, err := kp1.GetMultipartyPrivateKey()
	if err != nil {
		log.Fatal("GetMultipartyPrivateKey party 1:", err)
	}
	defer sk1.Close()

	sk2, err := kp2.GetMultipartyPrivateKey()
	if err != nil {
		log.Fatal("GetMultipartyPrivateKey party 2:", err)
	}
	defer sk2.Close()

	sk3, err := kp3.GetMultipartyPrivateKey()
	if err != nil {
		log.Fatal("GetMultipartyPrivateKey party 3:", err)
	}
	defer sk3.Close()

	// Lead party partial decryption
	fmt.Println("   Party 1: Performing lead decryption...")
	partial1, err := cc.MultipartyDecryptLead([]*openfhe.Ciphertext{ctResult}, sk1)
	if err != nil {
		log.Fatal("MultipartyDecryptLead:", err)
	}
	defer partial1[0].Close()

	// Main parties partial decryption
	fmt.Println("   Party 2: Performing partial decryption...")
	partial2, err := cc.MultipartyDecryptMain([]*openfhe.Ciphertext{ctResult}, sk2)
	if err != nil {
		log.Fatal("MultipartyDecryptMain party 2:", err)
	}
	defer partial2[0].Close()

	fmt.Println("   Party 3: Performing partial decryption...")
	partial3, err := cc.MultipartyDecryptMain([]*openfhe.Ciphertext{ctResult}, sk3)
	if err != nil {
		log.Fatal("MultipartyDecryptMain party 3:", err)
	}
	defer partial3[0].Close()

	// Fusion of partial decryptions
	fmt.Println("   Fusing partial decryptions...")
	partials := []*openfhe.Ciphertext{partial1[0], partial2[0], partial3[0]}
	ptResult, err := cc.MultipartyDecryptFusion(partials)
	if err != nil {
		log.Fatal("MultipartyDecryptFusion:", err)
	}
	defer ptResult.Close()

	// Step 8: Verify result
	fmt.Println("\n8. Verifying result...")
	result, err := ptResult.GetPackedValue()
	if err != nil {
		log.Fatal("GetPackedValue:", err)
	}

	// Calculate expected result
	expected := make([]int64, len(values1))
	for i := range expected {
		expected[i] = values1[i] + values2[i] + values3[i]
	}

	fmt.Printf("   Expected: %v\n", expected)
	fmt.Printf("   Got:      %v\n", result[:len(expected)])

	// Check if results match
	match := true
	for i := 0; i < len(expected); i++ {
		if result[i] != expected[i] {
			match = false
			break
		}
	}

	if match {
		fmt.Println("\n✓ Success! Threshold FHE decryption successful!")
		fmt.Println("  All three parties jointly decrypted the computation result.")
	} else {
		log.Fatal("Result mismatch!")
	}
}
