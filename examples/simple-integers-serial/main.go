package main

import (
	"fmt"
	"log"

	"github.com/dozyio/openfhe-go/openfhe"
)

// Helper to check errors
func checkErr(err error) {
	if err != nil {
		log.Fatalf("Error: %v", err) // Use log.Fatalf
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

	// --- Step 1: Setup CryptoContext ---
	parameters, err := openfhe.NewParamsBFVrns()
	checkErr(err)
	defer parameters.Close()

	checkErr(parameters.SetPlaintextModulus(65537))
	checkErr(parameters.SetMultiplicativeDepth(2))

	cc, err := openfhe.NewCryptoContextBFV(parameters)
	checkErr(err)
	// defer cc.Close() // We will close this later before loading

	checkErr(cc.Enable(openfhe.PKE))
	checkErr(cc.Enable(openfhe.KEYSWITCH))
	checkErr(cc.Enable(openfhe.LEVELEDSHE))
	fmt.Println("CryptoContext generated.")

	// --- Step 2: Key Generation ---
	keys, err := cc.KeyGen()
	checkErr(err)
	// defer keys.Close() // We will close this later before loading

	checkErr(cc.EvalMultKeyGen(keys)) // Generate relinearization key
	fmt.Println("Keys generated.")

	// --- Step 3: Encryption ---
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext, err := cc.MakePackedPlaintext(vectorOfInts)
	checkErr(err)
	// defer plaintext.Close() // We will close this later before loading

	ciphertext, err := cc.Encrypt(keys, plaintext)
	checkErr(err)
	// defer ciphertext.Close() // We will close this later before loading
	fmt.Println("Plaintext encrypted.")

	// --- Step 4: Serialization ---
	fmt.Println("\nSerializing objects...")

	// Serialize CryptoContext
	ccSerial, err := openfhe.SerializeCryptoContextToString(cc)
	checkErr(err)
	fmt.Println(" - CryptoContext serialized.")

	// Serialize Public Key
	pkSerial, err := openfhe.SerializePublicKeyToString(keys)
	checkErr(err)
	fmt.Println(" - Public Key serialized.")

	// Serialize Private Key
	skSerial, err := openfhe.SerializePrivateKeyToString(keys)
	checkErr(err)
	fmt.Println(" - Private Key serialized.")

	// Serialize Ciphertext
	ctSerial, err := openfhe.SerializeCiphertextToString(ciphertext)
	checkErr(err)
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
	ccLoaded := openfhe.DeserializeCryptoContextFromString(ccSerial)
	if ccLoaded == nil {
		panic("Failed to deserialize CryptoContext")
	}
	defer ccLoaded.Close() // Defer close for loaded object
	fmt.Println(" - CryptoContext deserialized.")

	// Deserialize Public Key
	kpPublic := openfhe.DeserializePublicKeyFromString(pkSerial)
	if kpPublic == nil {
		panic("Failed to deserialize Public Key")
	}
	defer kpPublic.Close() // Defer close for loaded object
	fmt.Println(" - Public Key deserialized.")

	// Deserialize Private Key
	kpPrivate := openfhe.DeserializePrivateKeyFromString(skSerial)
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

	// ... (EvalMultKey deserialization logic unchanged) ...

	// Deserialize Ciphertext
	ctLoaded := openfhe.DeserializeCiphertextFromString(ctSerial)
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

	fmt.Println("\n--- Results ---")
	fmt.Printf("Original vector: %v\n", truncateVector(vectorOfInts, 12))
	fmt.Printf("Decrypted vector:%v\n", truncateVector(resultVec, 12))
}
