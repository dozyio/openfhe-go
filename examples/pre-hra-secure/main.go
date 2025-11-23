package main

import (
	"fmt"
	"log"
	"math/rand"

	"github.com/dozyio/openfhe-go/openfhe"
)

// This example demonstrates HRA-secure (Honest Re-encryption Authority) Proxy Re-Encryption
// with noise flooding using the BGV scheme. This provides provable security for multi-hop PRE.
//
// Scenario: Alice encrypts her data and wants to share it through multiple proxy hops
// (up to 13 hops in this example) with strong security guarantees.

func main() {
	fmt.Println("HRA-Secure PRE Example - Multi-Hop Proxy Re-Encryption with BGV")
	fmt.Println("================================================================")

	const numHops = 13
	const plaintextModulus = 2 // binary plaintext

	fmt.Println("\nSetting up HRA-secure BGV PRE cryptosystem...")

	// Create BGV parameters
	params, err := openfhe.NewParamsBGVrns()
	if err != nil {
		log.Fatal("Failed to create BGV parameters:", err)
	}
	defer params.Close()

	// Configure parameters for HRA-secure PRE
	if err := params.SetPlaintextModulus(plaintextModulus); err != nil {
		log.Fatal("Failed to set plaintext modulus:", err)
	}

	if err := params.SetScalingTechnique(openfhe.FIXEDMANUAL); err != nil {
		log.Fatal("Failed to set scaling technique:", err)
	}

	// HRA-secure PRE specific parameters
	if err := params.SetPREMode(openfhe.NOISE_FLOODING_HRA); err != nil {
		log.Fatal("Failed to set PRE mode:", err)
	}

	if err := params.SetPRENumHops(numHops); err != nil {
		log.Fatal("Failed to set PRE num hops:", err)
	}

	if err := params.SetStatisticalSecurity(40); err != nil {
		log.Fatal("Failed to set statistical security:", err)
	}

	if err := params.SetNumAdversarialQueries(1048576); err != nil {
		log.Fatal("Failed to set num adversarial queries:", err)
	}

	if err := params.SetRingDim(32768); err != nil {
		log.Fatal("Failed to set ring dimension:", err)
	}

	if err := params.SetKeySwitchTechnique(openfhe.HYBRID); err != nil {
		log.Fatal("Failed to set key switch technique:", err)
	}

	if err := params.SetMultiplicativeDepth(0); err != nil {
		log.Fatal("Failed to set multiplicative depth:", err)
	}

	// Generate crypto context
	cc, err := openfhe.NewCryptoContextBGV(params)
	if err != nil {
		log.Fatal("Failed to create crypto context:", err)
	}
	defer cc.Close()

	// Enable features
	fmt.Println("Enabling PKE, KEYSWITCH, LEVELEDSHE, and PRE features...")
	if err := cc.Enable(openfhe.PKE); err != nil {
		log.Fatal("Failed to enable PKE:", err)
	}
	if err := cc.Enable(openfhe.KEYSWITCH); err != nil {
		log.Fatal("Failed to enable KEYSWITCH:", err)
	}
	if err := cc.Enable(openfhe.LEVELEDSHE); err != nil {
		log.Fatal("Failed to enable LEVELEDSHE:", err)
	}
	if err := cc.Enable(openfhe.PRE); err != nil {
		log.Fatal("Failed to enable PRE:", err)
	}

	ringSize := cc.GetRingDimension()
	fmt.Printf("\nRing dimension: %d\n", ringSize)
	fmt.Printf("Alice can encrypt %d bytes of data\n", ringSize/8)

	// Generate Alice's keys (original data owner)
	fmt.Println("\nGenerating Alice's keys (source data)...")
	aliceKeys, err := cc.KeyGen()
	if err != nil {
		log.Fatal("Failed to generate Alice's keys:", err)
	}
	defer aliceKeys.Close()

	// Create Alice's data (random binary values)
	fmt.Println("\nAlice creates her data...")
	aliceData := make([]int64, ringSize)
	for i := range aliceData {
		aliceData[i] = int64(rand.Intn(int(plaintextModulus)))
	}

	fmt.Printf("Sample of Alice's data (first 16 values): ")
	for i := 0; i < 16; i++ {
		fmt.Printf("%d", aliceData[i])
	}
	fmt.Println()

	// Create plaintext using coefficient packing (required for HRA-secure PRE)
	plaintext, err := cc.MakeCoefPackedPlaintext(aliceData)
	if err != nil {
		log.Fatal("Failed to create plaintext:", err)
	}
	defer plaintext.Close()

	// Alice encrypts her data
	fmt.Println("\nAlice encrypts her data...")
	ciphertext, err := cc.Encrypt(aliceKeys, plaintext)
	if err != nil {
		log.Fatal("Failed to encrypt:", err)
	}
	defer ciphertext.Close()

	// Verify Alice can decrypt
	fmt.Println("Verifying Alice can decrypt her own data...")
	decryptedAlice, err := cc.Decrypt(aliceKeys, ciphertext)
	if err != nil {
		log.Fatal("Failed to decrypt by Alice:", err)
	}
	defer decryptedAlice.Close()

	if err := decryptedAlice.SetLength(len(aliceData)); err != nil {
		log.Fatal("Failed to set plaintext length:", err)
	}

	// Generate keys for all proxy hops
	fmt.Printf("\nGenerating keys for %d proxy parties...\n", numHops)
	hopKeys := make([]*openfhe.KeyPair, numHops)
	reencryptionKeys := make([]*openfhe.EvalKey, numHops)

	for i := 0; i < numHops; i++ {
		hopKeys[i], err = cc.KeyGen()
		if err != nil {
			log.Fatalf("Failed to generate keys for hop %d: %v", i+1, err)
		}
		defer hopKeys[i].Close()

		// Generate re-encryption key
		if i == 0 {
			// First hop: from Alice to hop 1
			reencryptionKeys[i], err = cc.ReKeyGen(aliceKeys, hopKeys[i])
		} else {
			// Subsequent hops: from previous hop to current hop
			reencryptionKeys[i], err = cc.ReKeyGen(hopKeys[i-1], hopKeys[i])
		}
		if err != nil {
			log.Fatalf("Failed to generate re-encryption key for hop %d: %v", i+1, err)
		}
		defer reencryptionKeys[i].Close()
	}

	// Perform multi-hop re-encryption
	fmt.Println("\nPerforming multi-hop re-encryption...")
	currentCiphertext := ciphertext
	good := true

	for i := 0; i < numHops; i++ {
		fmt.Printf("Re-encrypting at hop %d/%d...\n", i+1, numHops)

		// Re-encrypt to next hop
		newCiphertext, err := cc.ReEncrypt(currentCiphertext, reencryptionKeys[i])
		if err != nil {
			log.Fatalf("Failed to re-encrypt at hop %d: %v", i+1, err)
		}

		// If not using the original ciphertext, close the previous one
		if i > 0 {
			currentCiphertext.Close()
		}
		currentCiphertext = newCiphertext
		defer currentCiphertext.Close()

		// ModReduce between hops (except for the last hop)
		if i < numHops-1 {
			if err := cc.ModReduceInPlace(currentCiphertext); err != nil {
				log.Fatalf("Failed to ModReduce at hop %d: %v", i+1, err)
			}
		}

		// Verify each hop can decrypt correctly
		decrypted, err := cc.Decrypt(hopKeys[i], currentCiphertext)
		if err != nil {
			log.Fatalf("Failed to decrypt at hop %d: %v", i+1, err)
		}
		defer decrypted.Close()

		if err := decrypted.SetLength(len(aliceData)); err != nil {
			log.Fatalf("Failed to set plaintext length at hop %d: %v", i+1, err)
		}

		// Get coefficient packed values for verification
		unpacked0, err := plaintext.GetCoefPackedValue()
		if err != nil {
			log.Fatalf("Failed to get original plaintext value at hop %d: %v", i+1, err)
		}

		unpacked1, err := decryptedAlice.GetCoefPackedValue()
		if err != nil {
			log.Fatalf("Failed to get Alice's decrypted value at hop %d: %v", i+1, err)
		}

		unpacked2, err := decrypted.GetCoefPackedValue()
		if err != nil {
			log.Fatalf("Failed to get hop %d decrypted value: %v", i+1, err)
		}

		// Note that OpenFHE assumes that plaintext is in the range of -p/2..p/2
		// To recover 0...p simply add p if the unpacked value is negative
		for j := 0; j < len(aliceData); j++ {
			if unpacked1[j] < 0 {
				unpacked1[j] += plaintextModulus
			}
			if unpacked2[j] < 0 {
				unpacked2[j] += plaintextModulus
			}
		}

		// Compare all the results for correctness
		for j := 0; j < len(aliceData); j++ {
			if (unpacked0[j] != unpacked1[j]) || (unpacked0[j] != unpacked2[j]) {
				good = false
			}
		}

		if good {
			fmt.Println("PRE passes")
		} else {
			fmt.Println("PRE fails")
		}
	}

	fmt.Println("\nExecution Completed.")

	if !good {
		log.Fatal("PRE test failed")
	}
}
