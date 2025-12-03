package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/dozyio/openfhe-go/openfhe"
)

const DATAFOLDER = "demoData"

func main() {
	fmt.Printf("This program requires the subdirectory `%s' to exist, otherwise you will get an error writing serializations.\n", DATAFOLDER)

	// Create data folder
	os.Mkdir(DATAFOLDER, 0o755) // Ignore error if exists

	// Sample Program: Step 1 - Set CryptoContext
	parameters, err := openfhe.NewParamsBGVrns()
	if err != nil {
		log.Fatalf("NewParamsBGVrns: %v", err)
	}
	defer parameters.Close()

	if err := parameters.SetMultiplicativeDepth(2); err != nil {
		log.Fatalf("SetMultiplicativeDepth: %v", err)
	}
	if err := parameters.SetPlaintextModulus(65537); err != nil {
		log.Fatalf("SetPlaintextModulus: %v", err)
	}

	cryptoContext, err := openfhe.NewCryptoContextBGV(parameters)
	if err != nil {
		log.Fatalf("NewCryptoContextBGV: %v", err)
	}
	// Enable features that you wish to use
	if err := cryptoContext.Enable(openfhe.PKE); err != nil {
		log.Fatalf("Enable PKE: %v", err)
	}
	if err := cryptoContext.Enable(openfhe.KEYSWITCH); err != nil {
		log.Fatalf("Enable KEYSWITCH: %v", err)
	}
	if err := cryptoContext.Enable(openfhe.LEVELEDSHE); err != nil {
		log.Fatalf("Enable LEVELEDSHE: %v", err)
	}

	fmt.Println("\nThe cryptocontext has been generated.")

	// Serialize cryptocontext
	ccBytes, err := openfhe.SerializeCryptoContextToBytes(cryptoContext)
	if err != nil {
		log.Fatalf("Error writing serialization of the crypto context to cryptocontext.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(DATAFOLDER, "cryptocontext.txt"), ccBytes, 0o644); err != nil {
		log.Fatalf("Error writing cryptocontext.txt: %v", err)
	}
	fmt.Println("The cryptocontext has been serialized.")

	// Sample Program: Step 2 - Key Generation

	// Initialize Public Key Containers
	// Generate a public/private key pair
	keyPair, err := cryptoContext.KeyGen()
	if err != nil {
		log.Fatalf("KeyGen: %v", err)
	}

	fmt.Println("The key pair has been generated.")

	// Serialize the public key
	pkBytes, err := openfhe.SerializePublicKeyToBytes(keyPair)
	if err != nil {
		log.Fatalf("Error writing serialization of public key to key-public.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(DATAFOLDER, "key-public.txt"), pkBytes, 0o644); err != nil {
		log.Fatalf("Error writing key-public.txt: %v", err)
	}
	fmt.Println("The public key has been serialized.")

	// Serialize the secret key
	skBytes, err := openfhe.SerializePrivateKeyToBytes(keyPair)
	if err != nil {
		log.Fatalf("Error writing serialization of private key to key-private.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(DATAFOLDER, "key-private.txt"), skBytes, 0o644); err != nil {
		log.Fatalf("Error writing key-private.txt: %v", err)
	}
	fmt.Println("The secret key has been serialized.")

	// Generate the relinearization key
	if err := cryptoContext.EvalMultKeyGen(keyPair); err != nil {
		log.Fatalf("EvalMultKeyGen: %v", err)
	}

	fmt.Println("The eval mult keys have been generated.")

	// Serialize the relinearization (evaluation) key for homomorphic multiplication
	emkeyBytes, err := openfhe.SerializeEvalMultKeyToBytes(cryptoContext, "")
	if err != nil {
		log.Fatalf("Error writing serialization of the eval mult keys to key-eval-mult.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(DATAFOLDER, "key-eval-mult.txt"), emkeyBytes, 0o644); err != nil {
		log.Fatalf("Error writing key-eval-mult.txt: %v", err)
	}
	fmt.Println("The eval mult keys have been serialized.")

	// Generate the rotation evaluation keys
	if err := cryptoContext.EvalRotateKeyGen(keyPair, []int32{1, 2, -1, -2}); err != nil {
		log.Fatalf("EvalRotateKeyGen: %v", err)
	}

	fmt.Println("The rotation keys have been generated.")

	// Serialize the rotation keys
	erkeyBytes, err := openfhe.SerializeEvalAutomorphismKeyToBytes(cryptoContext, "")
	if err != nil {
		log.Fatalf("Error writing serialization of the eval rotation keys to key-eval-rot.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(DATAFOLDER, "key-eval-rot.txt"), erkeyBytes, 0o644); err != nil {
		log.Fatalf("Error writing key-eval-rot.txt: %v", err)
	}
	fmt.Println("The eval rotation keys have been serialized.")

	// Sample Program: Step 3: Encryption

	// First plaintext vector is encoded
	vectorOfInts1 := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext1, err := cryptoContext.MakePackedPlaintext(vectorOfInts1)
	if err != nil {
		log.Fatalf("MakePackedPlaintext 1: %v", err)
	}
	// Second plaintext vector is encoded
	vectorOfInts2 := []int64{3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext2, err := cryptoContext.MakePackedPlaintext(vectorOfInts2)
	if err != nil {
		log.Fatalf("MakePackedPlaintext 2: %v", err)
	}
	// Third plaintext vector is encoded
	vectorOfInts3 := []int64{1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext3, err := cryptoContext.MakePackedPlaintext(vectorOfInts3)
	if err != nil {
		log.Fatalf("MakePackedPlaintext 3: %v", err)
	}

	pt1Val, _ := plaintext1.GetPackedValue()
	pt2Val, _ := plaintext2.GetPackedValue()
	pt3Val, _ := plaintext3.GetPackedValue()
	fmt.Printf("Plaintext #1: %v\n", pt1Val[:len(vectorOfInts1)])
	fmt.Printf("Plaintext #2: %v\n", pt2Val[:len(vectorOfInts2)])
	fmt.Printf("Plaintext #3: %v\n", pt3Val[:len(vectorOfInts3)])

	// The encoded vectors are encrypted
	ciphertext1, err := cryptoContext.Encrypt(keyPair, plaintext1)
	if err != nil {
		log.Fatalf("Encrypt 1: %v", err)
	}
	ciphertext2, err := cryptoContext.Encrypt(keyPair, plaintext2)
	if err != nil {
		log.Fatalf("Encrypt 2: %v", err)
	}
	ciphertext3, err := cryptoContext.Encrypt(keyPair, plaintext3)
	if err != nil {
		log.Fatalf("Encrypt 3: %v", err)
	}

	fmt.Println("The plaintexts have been encrypted.")

	ct1Bytes, err := openfhe.SerializeCiphertextToBytes(ciphertext1)
	if err != nil {
		log.Fatalf("Error writing serialization of ciphertext 1 to ciphertext1.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(DATAFOLDER, "ciphertext1.txt"), ct1Bytes, 0o644); err != nil {
		log.Fatalf("Error writing ciphertext1.txt: %v", err)
	}
	fmt.Println("The first ciphertext has been serialized.")

	ct2Bytes, err := openfhe.SerializeCiphertextToBytes(ciphertext2)
	if err != nil {
		log.Fatalf("Error writing serialization of ciphertext 2 to ciphertext2.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(DATAFOLDER, "ciphertext2.txt"), ct2Bytes, 0o644); err != nil {
		log.Fatalf("Error writing ciphertext2.txt: %v", err)
	}
	fmt.Println("The second ciphertext has been serialized.")

	ct3Bytes, err := openfhe.SerializeCiphertextToBytes(ciphertext3)
	if err != nil {
		log.Fatalf("Error writing serialization of ciphertext 3 to ciphertext3.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(DATAFOLDER, "ciphertext3.txt"), ct3Bytes, 0o644); err != nil {
		log.Fatalf("Error writing ciphertext3.txt: %v", err)
	}
	fmt.Println("The third ciphertext has been serialized.")

	// Sample Program: Step 4 - Evaluation

	// OpenFHE maintains an internal map of CryptoContext objects which are
	// indexed by a tag and the tag is applied to both the CryptoContext and some
	// of the keys. When deserializing a context, OpenFHE checks for the tag and
	// if it finds it in the CryptoContext map, it will return the stored version.
	// Hence, we need to clear the context and clear the keys.
	cryptoContext.ClearEvalMultKeys()
	cryptoContext.ClearEvalAutomorphismKeys()
	openfhe.ReleaseAllContexts()

	// Close original objects before deserializing
	cryptoContext.Close()
	keyPair.Close()
	plaintext1.Close()
	plaintext2.Close()
	plaintext3.Close()
	ciphertext1.Close()
	ciphertext2.Close()
	ciphertext3.Close()

	// Deserialize the crypto context
	ccBytes, err = os.ReadFile(filepath.Join(DATAFOLDER, "cryptocontext.txt"))
	if err != nil {
		log.Fatalf("I cannot read serialization from %s/cryptocontext.txt: %v", DATAFOLDER, err)
	}
	cc := openfhe.DeserializeCryptoContextFromBytes(ccBytes)
	if cc == nil {
		log.Fatalf("I cannot read serialization from %s/cryptocontext.txt", DATAFOLDER)
	}
	defer cc.Close()
	fmt.Println("The cryptocontext has been deserialized.")

	pkBytes, err = os.ReadFile(filepath.Join(DATAFOLDER, "key-public.txt"))
	if err != nil {
		log.Fatalf("Could not read public key: %v", err)
	}
	pk := openfhe.DeserializePublicKeyFromBytes(pkBytes)
	if pk == nil {
		log.Fatal("Could not read public key")
	}
	defer pk.Close()
	fmt.Println("The public key has been deserialized.")

	emkeyBytes, err = os.ReadFile(filepath.Join(DATAFOLDER, "key-eval-mult.txt"))
	if err != nil {
		log.Fatalf("I cannot read serialization from %s/key-eval-mult.txt: %v", DATAFOLDER, err)
	}
	if err := openfhe.DeserializeEvalMultKeyFromBytes(cc, emkeyBytes); err != nil {
		log.Fatalf("Could not deserialize the eval mult key file: %v", err)
	}
	fmt.Println("Deserialized the eval mult keys.")

	erkeyBytes, err = os.ReadFile(filepath.Join(DATAFOLDER, "key-eval-rot.txt"))
	if err != nil {
		log.Fatalf("I cannot read serialization from %s/key-eval-rot.txt: %v", DATAFOLDER, err)
	}
	if err := openfhe.DeserializeEvalAutomorphismKeyFromBytes(cc, erkeyBytes); err != nil {
		log.Fatalf("Could not deserialize the eval rotation key file: %v", err)
	}
	fmt.Println("Deserialized the eval rotation keys.")

	// deserializing ciphertexts
	ct1Bytes, err = os.ReadFile(filepath.Join(DATAFOLDER, "ciphertext1.txt"))
	if err != nil {
		log.Fatalf("Could not read the ciphertext: %v", err)
	}
	ct1 := openfhe.DeserializeCiphertextFromBytes(ct1Bytes)
	if ct1 == nil {
		log.Fatal("Could not read the ciphertext")
	}
	defer ct1.Close()
	fmt.Println("The first ciphertext has been deserialized.")

	ct2Bytes, err = os.ReadFile(filepath.Join(DATAFOLDER, "ciphertext2.txt"))
	if err != nil {
		log.Fatalf("Could not read the ciphertext: %v", err)
	}
	ct2 := openfhe.DeserializeCiphertextFromBytes(ct2Bytes)
	if ct2 == nil {
		log.Fatal("Could not read the ciphertext")
	}
	defer ct2.Close()
	fmt.Println("The second ciphertext has been deserialized.")

	ct3Bytes, err = os.ReadFile(filepath.Join(DATAFOLDER, "ciphertext3.txt"))
	if err != nil {
		log.Fatalf("Could not read the ciphertext: %v", err)
	}
	ct3 := openfhe.DeserializeCiphertextFromBytes(ct3Bytes)
	if ct3 == nil {
		log.Fatal("Could not read the ciphertext")
	}
	defer ct3.Close()
	fmt.Println("The third ciphertext has been deserialized.")

	// Homomorphic additions
	ciphertextAdd12, err := cc.EvalAdd(ct1, ct2)
	if err != nil {
		log.Fatalf("EvalAdd 1+2: %v", err)
	}
	defer ciphertextAdd12.Close()
	ciphertextAddResult, err := cc.EvalAdd(ciphertextAdd12, ct3)
	if err != nil {
		log.Fatalf("EvalAdd (1+2)+3: %v", err)
	}
	defer ciphertextAddResult.Close()

	// Homomorphic multiplications
	ciphertextMul12, err := cc.EvalMult(ct1, ct2)
	if err != nil {
		log.Fatalf("EvalMult 1*2: %v", err)
	}
	defer ciphertextMul12.Close()
	ciphertextMultResult, err := cc.EvalMult(ciphertextMul12, ct3)
	if err != nil {
		log.Fatalf("EvalMult (1*2)*3: %v", err)
	}
	defer ciphertextMultResult.Close()

	// Homomorphic rotations
	ciphertextRot1, err := cc.EvalRotate(ct1, 1)
	if err != nil {
		log.Fatalf("EvalRotate 1: %v", err)
	}
	defer ciphertextRot1.Close()
	ciphertextRot2, err := cc.EvalRotate(ct1, 2)
	if err != nil {
		log.Fatalf("EvalRotate 2: %v", err)
	}
	defer ciphertextRot2.Close()
	ciphertextRot3, err := cc.EvalRotate(ct1, -1)
	if err != nil {
		log.Fatalf("EvalRotate -1: %v", err)
	}
	defer ciphertextRot3.Close()
	ciphertextRot4, err := cc.EvalRotate(ct1, -2)
	if err != nil {
		log.Fatalf("EvalRotate -2: %v", err)
	}
	defer ciphertextRot4.Close()

	// Sample Program: Step 5 - Decryption

	skBytes, err = os.ReadFile(filepath.Join(DATAFOLDER, "key-private.txt"))
	if err != nil {
		log.Fatalf("Could not read secret key: %v", err)
	}
	sk := openfhe.DeserializePrivateKeyFromBytes(skBytes)
	if sk == nil {
		log.Fatal("Could not read secret key")
	}
	defer sk.Close()
	fmt.Println("The secret key has been deserialized.")

	// Reconstruct keypair for decryption
	keypairForDecrypt, err := openfhe.NewKeyPair()
	if err != nil {
		log.Fatalf("NewKeyPair: %v", err)
	}
	defer keypairForDecrypt.Close()

	pkPtr, err := pk.GetPublicKey()
	if err != nil {
		log.Fatalf("GetPublicKey: %v", err)
	}
	if err := keypairForDecrypt.SetPublicKey(pkPtr); err != nil {
		log.Fatalf("SetPublicKey: %v", err)
	}

	skPtr, err := sk.GetPrivateKey()
	if err != nil {
		log.Fatalf("GetPrivateKey: %v", err)
	}
	if err := keypairForDecrypt.SetPrivateKey(skPtr); err != nil {
		log.Fatalf("SetPrivateKey: %v", err)
	}

	// Decrypt the result of additions
	plaintextAddResult, err := cc.Decrypt(keypairForDecrypt, ciphertextAddResult)
	if err != nil {
		log.Fatalf("Decrypt Add: %v", err)
	}
	defer plaintextAddResult.Close()

	// Decrypt the result of multiplications
	plaintextMultResult, err := cc.Decrypt(keypairForDecrypt, ciphertextMultResult)
	if err != nil {
		log.Fatalf("Decrypt Mult: %v", err)
	}
	defer plaintextMultResult.Close()

	// Decrypt the result of rotations
	plaintextRot1, err := cc.Decrypt(keypairForDecrypt, ciphertextRot1)
	if err != nil {
		log.Fatalf("Decrypt Rot1: %v", err)
	}
	defer plaintextRot1.Close()
	plaintextRot2, err := cc.Decrypt(keypairForDecrypt, ciphertextRot2)
	if err != nil {
		log.Fatalf("Decrypt Rot2: %v", err)
	}
	defer plaintextRot2.Close()
	plaintextRot3, err := cc.Decrypt(keypairForDecrypt, ciphertextRot3)
	if err != nil {
		log.Fatalf("Decrypt Rot3: %v", err)
	}
	defer plaintextRot3.Close()
	plaintextRot4, err := cc.Decrypt(keypairForDecrypt, ciphertextRot4)
	if err != nil {
		log.Fatalf("Decrypt Rot4: %v", err)
	}
	defer plaintextRot4.Close()

	// Shows only the same number of elements as in the original plaintext vector
	// By default it will show all coefficients in the BGV-encoded polynomial
	if err := plaintextRot1.SetLength(len(vectorOfInts1)); err != nil {
		log.Fatalf("SetLength Rot1: %v", err)
	}
	if err := plaintextRot2.SetLength(len(vectorOfInts1)); err != nil {
		log.Fatalf("SetLength Rot2: %v", err)
	}
	if err := plaintextRot3.SetLength(len(vectorOfInts1)); err != nil {
		log.Fatalf("SetLength Rot3: %v", err)
	}
	if err := plaintextRot4.SetLength(len(vectorOfInts1)); err != nil {
		log.Fatalf("SetLength Rot4: %v", err)
	}

	// Output results
	fmt.Println("\nResults of homomorphic computations")

	valAdd, _ := plaintextAddResult.GetPackedValue()
	fmt.Printf("#1 + #2 + #3: %v\n", valAdd[:len(vectorOfInts1)])

	valMult, _ := plaintextMultResult.GetPackedValue()
	fmt.Printf("#1 * #2 * #3: %v\n", valMult[:len(vectorOfInts1)])

	valRot1, _ := plaintextRot1.GetPackedValue()
	fmt.Printf("Left rotation of #1 by 1: %v\n", valRot1)

	valRot2, _ := plaintextRot2.GetPackedValue()
	fmt.Printf("Left rotation of #1 by 2: %v\n", valRot2)

	valRot3, _ := plaintextRot3.GetPackedValue()
	fmt.Printf("Right rotation of #1 by 1: %v\n", valRot3)

	valRot4, _ := plaintextRot4.GetPackedValue()
	fmt.Printf("Right rotation of #1 by 2: %v\n", valRot4)
}
