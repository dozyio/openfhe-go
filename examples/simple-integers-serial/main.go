package main

import (
	"fmt"
	"os" // For basic file I/O (optional, can just use strings)

	"github.com/dozyio/openfhe-go/openfhe"
)

// Helper to check errors
func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

// Helper to truncate vector for printing
func truncateVector(vec []int64, maxLen int) []int64 {
	if len(vec) > maxLen {
		return vec[:maxLen]
	}
	return vec
}

func main() {
	fmt.Println("--- Go simple-integers-serial (BFV) example starting ---")
	dataDir := "demoData" // Directory to store serialized data (optional)
	os.MkdirAll(dataDir, os.ModePerm)

	// --- Step 1: Setup CryptoContext ---
	parameters := openfhe.NewParamsBFVrns()
	parameters.SetPlaintextModulus(65537)
	parameters.SetMultiplicativeDepth(2)
	cc := openfhe.NewCryptoContextBFV(parameters)
	cc.Enable(openfhe.PKE)
	cc.Enable(openfhe.KEYSWITCH)
	cc.Enable(openfhe.LEVELEDSHE)
	fmt.Println("CryptoContext generated.")

	// --- Step 2: Key Generation ---
	keys := cc.KeyGen()
	cc.EvalMultKeyGen(keys) // Generate relinearization key
	fmt.Println("Keys generated.")

	// --- Step 3: Encryption ---
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := cc.MakePackedPlaintext(vectorOfInts)
	ciphertext := cc.Encrypt(keys, plaintext)
	fmt.Println("Plaintext encrypted.")

	// --- Step 4: Serialization ---
	fmt.Println("\nSerializing objects...")

	// Serialize CryptoContext
	ccSerial, err := openfhe.SerializeCryptoContextToString(cc)
	checkErr(err)
	// Optional: Write to file
	// os.WriteFile(dataDir+"/cryptocontext.json", []byte(ccSerial), 0644)
	fmt.Println(" - CryptoContext serialized.")

	// Serialize Public Key
	pkSerial, err := openfhe.SerializePublicKeyToString(keys)
	checkErr(err)
	// os.WriteFile(dataDir+"/key-public.json", []byte(pkSerial), 0644)
	fmt.Println(" - Public Key serialized.")

	// Serialize Private Key
	skSerial, err := openfhe.SerializePrivateKeyToString(keys)
	checkErr(err)
	// os.WriteFile(dataDir+"/key-private.json", []byte(skSerial), 0644)
	fmt.Println(" - Private Key serialized.")

	// Serialize EvalMultKey (Relinearization Key)
	// Need the secret key's ID (usually its fingerprint in OpenFHE)
	// NOTE: Getting the key ID efficiently via CGO might require another bridge function.
	// For this example, we'll assume a known ID or skip file saving which relies on it.
	// Let's serialize it but maybe not save it to a file easily without the ID.
	// In OpenFHE C++, the ID is often implicitly derived when serializing *from* the CC.
	// Let's try passing an empty string - it *might* work for the default key.
	// evalMultKeySerial, err := openfhe.SerializeEvalMultKeyToString(cc, "")
	// if err != nil {
	// 	fmt.Printf("Warning: Could not serialize EvalMultKey: %v\n", err)
	// } else {
	// 	// os.WriteFile(dataDir+"/key-eval-mult.json", []byte(evalMultKeySerial), 0644)
	// 	fmt.Println(" - EvalMultKey serialized (attempted).")
	// }

	// Serialize Ciphertext
	ctSerial, err := openfhe.SerializeCiphertextToString(ciphertext)
	checkErr(err)
	// os.WriteFile(dataDir+"/ciphertext.json", []byte(ctSerial), 0644)
	fmt.Println(" - Ciphertext serialized.")

	// --- Clear objects (demonstrate loading) ---
	// In Go, we rely on GC, but let's simulate clearing by setting to nil
	cc = nil
	keys = nil
	plaintext = nil
	ciphertext = nil
	// Can't easily nil the internal C++ pointers without explicit destroy,
	// but assigning nil removes Go's reference, allowing GC (eventually).

	fmt.Println("\nOriginal objects cleared (set to nil).")

	// --- Step 5: Deserialization ---
	fmt.Println("\nDeserializing objects...")

	// Deserialize CryptoContext
	ccLoaded := openfhe.DeserializeCryptoContextFromString(ccSerial)
	if ccLoaded == nil {
		panic("Failed to deserialize CryptoContext")
	}
	fmt.Println(" - CryptoContext deserialized.")

	// Deserialize Public Key
	kpPublic := openfhe.DeserializePublicKeyFromString(pkSerial)
	if kpPublic == nil {
		panic("Failed to deserialize Public Key")
	}
	fmt.Println(" - Public Key deserialized.")

	// Deserialize Private Key
	kpPrivate := openfhe.DeserializePrivateKeyFromString(skSerial)
	if kpPrivate == nil {
		panic("Failed to deserialize Private Key")
	}
	fmt.Println(" - Private Key deserialized.")

	// Combine keys into a single KeyPair struct
	keysLoaded := openfhe.NewKeyPair()
	keysLoaded.SetPublicKey(kpPublic.GetPublicKey())    // Extracts PK pointer
	keysLoaded.SetPrivateKey(kpPrivate.GetPrivateKey()) // Extracts SK pointer
	// kpPublic and kpPrivate can now go out of scope / be GC'd if desired

	// Deserialize EvalMultKey (load into the deserialized context)
	// if evalMultKeySerial != "" {
	// 	err = openfhe.DeserializeEvalMultKeyFromString(ccLoaded, evalMultKeySerial)
	// 	if err != nil {
	// 		fmt.Printf("Warning: Could not deserialize EvalMultKey: %v\n", err)
	// 	} else {
	// 		fmt.Println(" - EvalMultKey deserialized (attempted).")
	// 	}
	// } else {
	// 	fmt.Println(" - EvalMultKey serialization was skipped, cannot deserialize.")
	// }

	// Deserialize Ciphertext
	ctLoaded := openfhe.DeserializeCiphertextFromString(ctSerial)
	if ctLoaded == nil {
		panic("Failed to deserialize Ciphertext")
	}
	fmt.Println(" - Ciphertext deserialized.")

	// --- Step 6: Decryption using loaded objects ---
	fmt.Println("\nDecrypting loaded ciphertext...")
	plaintextLoaded := ccLoaded.Decrypt(keysLoaded, ctLoaded) // Use loaded CC, Keys, CT

	fmt.Println("\n--- Results ---")
	fmt.Printf("Original vector: %v\n", truncateVector(vectorOfInts, 12))
	fmt.Printf("Decrypted vector:%v\n", truncateVector(plaintextLoaded.GetPackedValue(), 12))
}
