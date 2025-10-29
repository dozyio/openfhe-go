package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/dozyio/openfhe-go/openfhe"
)

// Helper to check errors
func checkErr(err error) {
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}

// Helper to truncate vector for printing
func truncateVector(vec []int64, maxLen int) []int64 {
	if len(vec) > maxLen {
		return vec[:maxLen]
	}
	return vec
}

// Helper to compare integer slices
func slicesEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func main() {
	fmt.Println("--- Go simple-integers-serial (BFV) example starting ---")

	dataDir := "demoData"
	os.Mkdir(dataDir, 0o755) // Ignore error if exists

	// Define file paths
	ccPath := filepath.Join(dataDir, "cryptocontext-bfv.bin")
	pkPath := filepath.Join(dataDir, "key-public-bfv.bin")
	skPath := filepath.Join(dataDir, "key-secret-bfv.bin")
	ctPath := filepath.Join(dataDir, "ciphertext-bfv.bin")

	// --- Step 1: Setup CryptoContext ---
	parameters, err := openfhe.NewParamsBFVrns()
	checkErr(err)
	defer parameters.Close()

	checkErr(parameters.SetPlaintextModulus(65537))
	checkErr(parameters.SetMultiplicativeDepth(2))

	cc, err := openfhe.NewCryptoContextBFV(parameters)
	checkErr(err)
	// We will close this later before loading

	checkErr(cc.Enable(openfhe.PKE))
	checkErr(cc.Enable(openfhe.KEYSWITCH))
	checkErr(cc.Enable(openfhe.LEVELEDSHE))
	fmt.Println("CryptoContext generated.")

	// --- Step 2: Key Generation ---
	keys, err := cc.KeyGen()
	checkErr(err)
	// We will close this later before loading

	checkErr(cc.EvalMultKeyGen(keys)) // Generate relinearization key
	fmt.Println("Keys generated.")

	// --- Step 3: Encryption ---
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext, err := cc.MakePackedPlaintext(vectorOfInts)
	checkErr(err)
	// We will close this later before loading

	ciphertext, err := cc.Encrypt(keys, plaintext)
	checkErr(err)
	// We will close this later before loading
	fmt.Println("Plaintext encrypted.")

	// --- Step 4: Serialization ---
	fmt.Println("\nSerializing objects...")

	// Serialize CryptoContext
	ccBytes, err := openfhe.SerializeCryptoContextToBytes(cc) // CHANGED
	checkErr(err)
	checkErr(os.WriteFile(ccPath, ccBytes, 0o644))
	fmt.Println(" - CryptoContext serialized.")

	// Serialize Public Key
	pkBytes, err := openfhe.SerializePublicKeyToBytes(keys) // CHANGED
	checkErr(err)
	checkErr(os.WriteFile(pkPath, pkBytes, 0o644))
	fmt.Println(" - Public Key serialized.")

	// Serialize Private Key
	skBytes, err := openfhe.SerializePrivateKeyToBytes(keys) // CHANGED
	checkErr(err)
	checkErr(os.WriteFile(skPath, skBytes, 0o644))
	fmt.Println(" - Private Key serialized.")

	// Serialize Ciphertext
	ctBytes, err := openfhe.SerializeCiphertextToBytes(ciphertext) // CHANGED
	checkErr(err)
	checkErr(os.WriteFile(ctPath, ctBytes, 0o644))
	fmt.Println(" - Ciphertext serialized.")

	// --- Clear objects (demonstrate loading) ---
	// Close the C++ objects before nil-ing the Go vars
	cc.Close()
	keys.Close()
	plaintext.Close()
	ciphertext.Close()

	cc = nil
	keys = nil
	plaintext = nil
	ciphertext = nil

	fmt.Println("\nOriginal objects cleared (closed and set to nil).")

	// --- Step 5: Deserialization ---
	fmt.Println("\nDeserializing objects...")

	// Deserialize CryptoContext
	ccBytes, err = os.ReadFile(ccPath)
	checkErr(err)
	ccLoaded := openfhe.DeserializeCryptoContextFromBytes(ccBytes) // CHANGED
	if ccLoaded == nil {
		panic("Failed to deserialize CryptoContext")
	}
	defer ccLoaded.Close() // Defer close for loaded object
	fmt.Println(" - CryptoContext deserialized.")

	// Re-enable features
	checkErr(ccLoaded.Enable(openfhe.PKE))
	checkErr(ccLoaded.Enable(openfhe.KEYSWITCH))
	checkErr(ccLoaded.Enable(openfhe.LEVELEDSHE))
	fmt.Println(" - Features re-enabled.")

	// Deserialize Public Key
	pkBytes, err = os.ReadFile(pkPath)
	checkErr(err)
	kpPublic := openfhe.DeserializePublicKeyFromBytes(pkBytes) // CHANGED
	if kpPublic == nil {
		panic("Failed to deserialize Public Key")
	}
	defer kpPublic.Close() // Defer close for loaded object
	fmt.Println(" - Public Key deserialized.")

	// Deserialize Private Key
	skBytes, err = os.ReadFile(skPath)
	checkErr(err)
	kpPrivate := openfhe.DeserializePrivateKeyFromBytes(skBytes) // CHANGED
	if kpPrivate == nil {
		panic("Failed to deserialize Private Key")
	}
	defer kpPrivate.Close() // Defer close for loaded object
	fmt.Println(" - Private Key deserialized.")

	// Combine keys into a single KeyPair struct
	keysLoaded, err := openfhe.NewKeyPair()
	checkErr(err)
	defer keysLoaded.Close() // Defer close for loaded object

	pkPtr, err := kpPublic.GetPublicKey() // Get pointer
	checkErr(err)
	checkErr(keysLoaded.SetPublicKey(pkPtr)) // Set pointer

	skPtr, err := kpPrivate.GetPrivateKey() // Get pointer
	checkErr(err)
	checkErr(keysLoaded.SetPrivateKey(skPtr)) // Set pointer
	fmt.Println(" - KeyPair reconstructed.")

	// Deserialize Ciphertext
	ctBytes, err = os.ReadFile(ctPath)
	checkErr(err)
	ctLoaded := openfhe.DeserializeCiphertextFromBytes(ctBytes) // CHANGED
	if ctLoaded == nil {
		panic("Failed to deserialize Ciphertext")
	}
	defer ctLoaded.Close() // Defer close for loaded object
	fmt.Println(" - Ciphertext deserialized.")

	// --- Step 6: Decryption using loaded objects ---
	fmt.Println("\nDecrypting loaded ciphertext...")
	plaintextLoaded, err := ccLoaded.Decrypt(keysLoaded, ctLoaded) // Use loaded CC, Keys, CT
	checkErr(err)
	defer plaintextLoaded.Close()

	resultVec, err := plaintextLoaded.GetPackedValue()
	checkErr(err)

	// --- Verification ---
	fmt.Println("\n--- Results ---")
	fmt.Printf("Original vector: %v\n", truncateVector(vectorOfInts, 12))
	fmt.Printf("Decrypted vector:%v\n", truncateVector(resultVec, 12))

	// Check for match
	if !slicesEqual(vectorOfInts, resultVec[:len(vectorOfInts)]) {
		log.Fatal("Decryption FAILED: vectors do not match.")
	}
	fmt.Println("Decryption SUCCESS: vectors match.")
	fmt.Println("--- Go simple-integers-serial (BFV) example finished ---")
}
