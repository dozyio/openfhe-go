package main

import (
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"

	"github.com/dozyio/openfhe-go/openfhe"
)

func main() {
	fmt.Println("OpenFHE CKKS Serialization Example")

	dataDir := "demoData"
	os.Mkdir(dataDir, 0o755) // Ignore error if exists

	// --- Step 1: Set CryptoContext ---
	parameters, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		log.Fatalf("Failed to create CKKS parameters: %v", err)
	}
	defer parameters.Close()

	// Parameters based on Python example
	parameters.SetScalingModSize(40)
	parameters.SetBatchSize(8)
	parameters.SetMultiplicativeDepth(5)

	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	if err != nil {
		log.Fatalf("Failed to create CryptoContext: %v", err)
	}
	defer cc.Close()

	cc.Enable(openfhe.PKE)
	cc.Enable(openfhe.KEYSWITCH)
	cc.Enable(openfhe.LEVELEDSHE)

	fmt.Println("CKKS scheme is using ring dimension:", cc.GetRingDimension())
	fmt.Println()

	// --- Step 2: Key Generation ---
	keys, err := cc.KeyGen()
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}
	defer keys.Close()
	err = cc.EvalMultKeyGen(keys)
	if err != nil {
		log.Fatalf("EvalMultKeyGen failed: %v", err)
	}

	// --- Step 3: Encoding and Encryption ---
	vectorOfDouble1 := []float64{0.5, 0.7, 0.9, 0.2}
	vectorOfDouble2 := []float64{0.1, 0.2, 0.3, 0.4}

	ptxt1, err := cc.MakeCKKSPackedPlaintext(vectorOfDouble1)
	if err != nil {
		log.Fatalf("MakeCKKSPackedPlaintext ptxt1 failed: %v", err)
	}
	defer ptxt1.Close()
	ptxt2, err := cc.MakeCKKSPackedPlaintext(vectorOfDouble2)
	if err != nil {
		log.Fatalf("MakeCKKSPackedPlaintext ptxt2 failed: %v", err)
	}
	defer ptxt2.Close()

	fmt.Printf("Input vector 1: %v\n", vectorOfDouble1)
	fmt.Printf("Input vector 2: %v\n", vectorOfDouble2)

	ciphertext1, err := cc.Encrypt(keys, ptxt1)
	if err != nil {
		log.Fatalf("Encrypt ciphertext1 failed: %v", err)
	}
	defer ciphertext1.Close()
	ciphertext2, err := cc.Encrypt(keys, ptxt2)
	if err != nil {
		log.Fatalf("Encrypt ciphertext2 failed: %v", err)
	}
	defer ciphertext2.Close()

	// --- Step 4: Homomorphic Addition ---
	ciphertextAdd, err := cc.EvalAdd(ciphertext1, ciphertext2)
	if err != nil {
		log.Fatalf("EvalAdd failed: %v", err)
	}
	defer ciphertextAdd.Close()

	// --- Pre-Serialization Check ---
	fmt.Println("\n--- Decrypting BEFORE serialization ---")
	ptxtAddResTmp, errTmp := cc.Decrypt(keys, ciphertextAdd)
	if errTmp != nil {
		log.Fatalf("Decryption BEFORE serialization failed: %v", errTmp)
	}
	errTmp = ptxtAddResTmp.SetLength(len(vectorOfDouble1))
	if errTmp != nil {
		log.Fatalf("SetLength failed before serialization: %v", errTmp)
	}
	resVecTmp, errTmp := ptxtAddResTmp.GetRealPackedValue()
	if errTmp != nil {
		log.Fatalf("GetRealPackedValue failed before serialization: %v", errTmp)
	}
	fmt.Printf("Result before serialization: %v\n", resVecTmp[:len(vectorOfDouble1)])
	ptxtAddResTmp.Close()
	fmt.Println("--- Finished decrypting BEFORE serialization ---")

	// --- Step 5: Serialization ---
	fmt.Println("\nSerializing objects...")

	// Define file paths
	ccPath := filepath.Join(dataDir, "cryptocontext.bin")
	pkPath := filepath.Join(dataDir, "key-public.bin")
	skPath := filepath.Join(dataDir, "key-secret.bin")
	// Note: We don't need to serialize EvalMultKey separately
	// multKeyPath := filepath.Join(dataDir, "key-eval-mult.bin")
	ctAddPath := filepath.Join(dataDir, "ciphertext-add.bin")

	// Serialize CryptoContext (contains EvalMultKey)
	ccBytes, err := openfhe.SerializeCryptoContextToBytes(cc)
	if err != nil {
		log.Fatalf("Error serializing CryptoContext: %v", err)
	}
	err = os.WriteFile(ccPath, ccBytes, 0o644)
	if err != nil {
		log.Fatalf("Error writing CryptoContext: %v", err)
	}

	// Serialize Public Key
	pkBytes, err := openfhe.SerializePublicKeyToBytes(keys)
	if err != nil {
		log.Fatalf("Error serializing PublicKey: %v", err)
	}
	err = os.WriteFile(pkPath, pkBytes, 0o644)
	if err != nil {
		log.Fatalf("Error writing PublicKey: %v", err)
	}

	// Serialize Private Key
	skBytes, err := openfhe.SerializePrivateKeyToBytes(keys)
	if err != nil {
		log.Fatalf("Error serializing PrivateKey: %v", err)
	}
	err = os.WriteFile(skPath, skBytes, 0o644)
	if err != nil {
		log.Fatalf("Error writing PrivateKey: %v", err)
	}

	// Serialize Ciphertext
	ctAddBytes, err := openfhe.SerializeCiphertextToBytes(ciphertextAdd)
	if err != nil {
		log.Fatalf("Error serializing ciphertext add: %v", err)
	}
	err = os.WriteFile(ctAddPath, ctAddBytes, 0o644)
	if err != nil {
		log.Fatalf("Error writing ciphertext add: %v", err)
	}

	fmt.Println("Serialization completed.")

	// --- Step 6: Clear Objects (Simulate Transfer) ---
	fmt.Println("\nClearing original objects (simulation).")
	ciphertextAdd.Close()
	ciphertext2.Close()
	ciphertext1.Close()
	ptxt2.Close()
	ptxt1.Close()
	keys.Close()
	cc.Close()

	cc = nil
	keys = nil
	ptxt1 = nil
	ptxt2 = nil
	ciphertext1 = nil
	ciphertext2 = nil
	ciphertextAdd = nil

	// --- Step 7: Deserialization ---
	fmt.Println("\nDeserializing objects...")

	// Deserialize CryptoContext
	ccBytes, err = os.ReadFile(ccPath)
	if err != nil {
		log.Fatalf("Error reading CryptoContext: %v", err)
	}
	ccNew := openfhe.DeserializeCryptoContextFromBytes(ccBytes)
	if ccNew == nil {
		log.Fatalf("DeserializeCryptoContextFromBytes failed")
	}
	defer ccNew.Close()

	// Re-enable features to rebuild transient state
	fmt.Println("Go: Re-enabling features on deserialized context...")
	err = ccNew.Enable(openfhe.PKE)
	if err != nil {
		log.Fatalf("Failed to re-enable PKE: %v", err)
	}
	err = ccNew.Enable(openfhe.KEYSWITCH)
	if err != nil {
		log.Fatalf("Failed to re-enable KEYSWITCH: %v", err)
	}
	err = ccNew.Enable(openfhe.LEVELEDSHE)
	if err != nil {
		log.Fatalf("Failed to re-enable LEVELEDSHE: %v", err)
	}
	fmt.Println("Go: Features re-enabled.")

	// Deserialize Public Key
	pkBytes, err = os.ReadFile(pkPath)
	if err != nil {
		log.Fatalf("Error reading Public Key: %v", err)
	}
	kpPublicOnly := openfhe.DeserializePublicKeyFromBytes(pkBytes)
	if kpPublicOnly == nil {
		log.Fatalf("DeserializePublicKeyFromBytes failed")
	}
	defer kpPublicOnly.Close()

	// Deserialize Private Key
	fmt.Println("Go: Deserializing PrivateKey...")
	skBytes, err = os.ReadFile(skPath)
	if err != nil {
		log.Fatalf("Error reading Private Key: %v", err)
	}
	kpPrivateOnly := openfhe.DeserializePrivateKeyFromBytes(skBytes)
	if kpPrivateOnly == nil {
		log.Fatalf("DeserializePrivateKeyFromBytes failed")
	}
	defer kpPrivateOnly.Close()
	fmt.Println("Go: Deserializing PrivateKey successful.")

	// Deserialize Ciphertext
	ctAddBytes, err = os.ReadFile(ctAddPath)
	if err != nil {
		log.Fatalf("Error reading ciphertext add: %v", err)
	}
	ctAddNew := openfhe.DeserializeCiphertextFromBytes(ctAddBytes)
	if ctAddNew == nil {
		log.Fatalf("DeserializeCiphertextFromBytes ctAdd failed")
	}
	defer ctAddNew.Close()

	fmt.Println("Deserialization completed.")

	// --- Step 8: Decryption and Verification ---

	// Reconstruct the full KeyPair
	fmt.Println("Go: Reconstructing KeyPair...")
	keysNew, err := openfhe.NewKeyPair()
	if err != nil {
		log.Fatalf("NewKeyPair failed: %v", err)
	}
	defer keysNew.Close()

	pkPtr, err := kpPublicOnly.GetPublicKey()
	if err != nil {
		log.Fatalf("GetPublicKey failed: %v", err)
	}
	skPtr, err := kpPrivateOnly.GetPrivateKey()
	if err != nil {
		log.Fatalf("GetPrivateKey failed: %v", err)
	}

	err = keysNew.SetPublicKey(pkPtr)
	if err != nil {
		log.Fatalf("SetPublicKey failed: %v", err)
	}
	err = keysNew.SetPrivateKey(skPtr)
	if err != nil {
		log.Fatalf("SetPrivateKey failed: %v", err)
	}
	fmt.Println("Go: KeyPair reconstructed.")

	// Decrypt using the reconstructed keys
	ptxtAddRes, err := ccNew.Decrypt(keysNew, ctAddNew)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	defer ptxtAddRes.Close()

	// --- Verification ---
	err = ptxtAddRes.SetLength(len(vectorOfDouble1))
	if err != nil {
		log.Fatalf("Failed to set plaintext length: %v", err)
	}
	resultVector, err := ptxtAddRes.GetRealPackedValue()
	if err != nil {
		log.Fatalf("Error getting packed real values: %v", err)
	}

	fmt.Println("\nResults:")
	fmt.Printf("Original vector 1: %v\n", vectorOfDouble1)
	fmt.Printf("Original vector 2: %v\n", vectorOfDouble2)
	fmt.Printf("Result of addition: %v\n", resultVector[:len(vectorOfDouble1)])

	expectedResult := make([]float64, len(vectorOfDouble1))
	for i := range vectorOfDouble1 {
		expectedResult[i] = vectorOfDouble1[i] + vectorOfDouble2[i]
	}

	tolerance := 0.0001
	match := true
	if len(resultVector) < len(expectedResult) {
		fmt.Println("Result vector is shorter than expected!")
		match = false
	} else {
		for i := range expectedResult {
			if math.Abs(resultVector[i]-expectedResult[i]) > tolerance {
				fmt.Printf("Mismatch at index %d: Expected %.5f, Got %.5f\n", i, expectedResult[i], resultVector[i])
				match = false
			}
		}
	}

	if match {
		fmt.Println("Addition results verified successfully!")
	} else {
		fmt.Println("Addition results verification failed!")
	}
}
