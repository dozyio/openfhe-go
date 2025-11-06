// Port of OpenFHE C++ example: src/pke/examples/inner-product.cpp
// Simple example for BFV and CKKS for inner product using EvalInnerProduct.

package main

import (
	"fmt"
	"log"
	"math"

	"github.com/dozyio/openfhe-go/openfhe"
)

// plainInnerProduct computes the inner product of a vector with itself
// Returns sum(vec[i] * vec[i])
func plainInnerProductInt(vec []int64) int64 {
	var result int64
	for _, el := range vec {
		result += el * el
	}
	return result
}

func plainInnerProductFloat(vec []float64) float64 {
	var result float64
	for _, el := range vec {
		result += el * el
	}
	return result
}

func innerProductBFV(incomingVector []int64) bool {
	expectedResult := plainInnerProductInt(incomingVector)

	// Crypto Parameters
	parameters, err := openfhe.NewParamsBFVrns()
	if err != nil {
		log.Fatalf("NewParamsBFVrns failed: %v", err)
	}
	defer parameters.Close()

	if err := parameters.SetPlaintextModulus(65537); err != nil {
		log.Fatalf("SetPlaintextModulus failed: %v", err)
	}
	if err := parameters.SetMultiplicativeDepth(20); err != nil {
		log.Fatalf("SetMultiplicativeDepth failed: %v", err)
	}
	if err := parameters.SetSecurityLevel(openfhe.HEStdNotSet); err != nil {
		log.Fatalf("SetSecurityLevel failed: %v", err)
	}
	if err := parameters.SetRingDim(1 << 7); err != nil { // 128
		log.Fatalf("SetRingDim failed: %v", err)
	}

	batchSize := uint32((1 << 7) / 2) // ringDim / 2 = 64

	// Set crypto params and create context
	cc, err := openfhe.NewCryptoContextBFV(parameters)
	if err != nil {
		log.Fatalf("NewCryptoContextBFV failed: %v", err)
	}
	defer cc.Close()

	// Enable the features that you wish to use
	if err := cc.Enable(openfhe.PKE); err != nil {
		log.Fatalf("Enable PKE failed: %v", err)
	}
	if err := cc.Enable(openfhe.LEVELEDSHE); err != nil {
		log.Fatalf("Enable LEVELEDSHE failed: %v", err)
	}
	if err := cc.Enable(openfhe.ADVANCEDSHE); err != nil {
		log.Fatalf("Enable ADVANCEDSHE failed: %v", err)
	}

	keys, err := cc.KeyGen()
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}
	defer keys.Close()

	if err := cc.EvalMultKeyGen(keys); err != nil {
		log.Fatalf("EvalMultKeyGen failed: %v", err)
	}
	if err := cc.EvalSumKeyGen(keys); err != nil {
		log.Fatalf("EvalSumKeyGen failed: %v", err)
	}

	plaintext1, err := cc.MakePackedPlaintext(incomingVector)
	if err != nil {
		log.Fatalf("MakePackedPlaintext failed: %v", err)
	}
	defer plaintext1.Close()

	ct1, err := cc.Encrypt(keys, plaintext1)
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}
	defer ct1.Close()

	finalResult, err := cc.EvalInnerProduct(ct1, ct1, batchSize)
	if err != nil {
		log.Fatalf("EvalInnerProduct failed: %v", err)
	}
	defer finalResult.Close()

	res, err := cc.Decrypt(keys, finalResult)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}
	defer res.Close()

	result, err := res.GetPackedValue()
	if err != nil {
		log.Fatalf("GetPackedValue failed: %v", err)
	}

	final := result[0]
	fmt.Printf("Expected Result: %d Inner Product Result: %d\n", expectedResult, final)
	return expectedResult == final
}

func innerProductCKKS(incomingVector []float64) bool {
	expectedResult := plainInnerProductFloat(incomingVector)

	// Crypto Parameters
	securityLevel := openfhe.HEStdNotSet
	dcrtBits := uint32(59)
	ringDim := uint64(1 << 8) // 256
	batchSize := uint32(ringDim / 2)
	multDepth := 10

	parameters, err := openfhe.NewParamsCKKSRNS()
	if err != nil {
		log.Fatalf("NewParamsCKKSRNS failed: %v", err)
	}
	defer parameters.Close()

	if err := parameters.SetMultiplicativeDepth(multDepth); err != nil {
		log.Fatalf("SetMultiplicativeDepth failed: %v", err)
	}
	if err := parameters.SetScalingModSize(int(dcrtBits)); err != nil {
		log.Fatalf("SetScalingModSize failed: %v", err)
	}
	if err := parameters.SetBatchSize(int(batchSize)); err != nil {
		log.Fatalf("SetBatchSize failed: %v", err)
	}
	if err := parameters.SetSecurityLevel(securityLevel); err != nil {
		log.Fatalf("SetSecurityLevel failed: %v", err)
	}
	if err := parameters.SetRingDim(ringDim); err != nil {
		log.Fatalf("SetRingDim failed: %v", err)
	}

	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	if err != nil {
		log.Fatalf("NewCryptoContextCKKS failed: %v", err)
	}
	defer cc.Close()

	if err := cc.Enable(openfhe.PKE); err != nil {
		log.Fatalf("Enable PKE failed: %v", err)
	}
	if err := cc.Enable(openfhe.LEVELEDSHE); err != nil {
		log.Fatalf("Enable LEVELEDSHE failed: %v", err)
	}
	if err := cc.Enable(openfhe.ADVANCEDSHE); err != nil {
		log.Fatalf("Enable ADVANCEDSHE failed: %v", err)
	}

	keys, err := cc.KeyGen()
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}
	defer keys.Close()

	if err := cc.EvalMultKeyGen(keys); err != nil {
		log.Fatalf("EvalMultKeyGen failed: %v", err)
	}
	if err := cc.EvalSumKeyGen(keys); err != nil {
		log.Fatalf("EvalSumKeyGen failed: %v", err)
	}

	plaintext1, err := cc.MakeCKKSPackedPlaintext(incomingVector)
	if err != nil {
		log.Fatalf("MakeCKKSPackedPlaintext failed: %v", err)
	}
	defer plaintext1.Close()

	ct1, err := cc.Encrypt(keys, plaintext1)
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}
	defer ct1.Close()

	finalResult, err := cc.EvalInnerProduct(ct1, ct1, batchSize)
	if err != nil {
		log.Fatalf("EvalInnerProduct failed: %v", err)
	}
	defer finalResult.Close()

	res, err := cc.Decrypt(keys, finalResult)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}
	defer res.Close()

	if err := res.SetLength(len(incomingVector)); err != nil {
		log.Fatalf("SetLength failed: %v", err)
	}

	result, err := res.GetRealPackedValue()
	if err != nil {
		log.Fatalf("GetRealPackedValue failed: %v", err)
	}

	final := result[0]
	fmt.Printf("Expected Result: %.4f Inner Product Result: %.4f\n", expectedResult, final)
	return math.Abs(expectedResult-final) <= 0.0001
}

func main() {
	fmt.Println("Inner Product Example")
	fmt.Println("Port of OpenFHE C++ example: src/pke/examples/inner-product.cpp")
	fmt.Println("=====================================================================")
	fmt.Println()

	vec := []int64{1, 2, 3, 4, 5}

	fmt.Println("--- BFV Inner Product ---")
	bfvRes := innerProductBFV(vec)
	fmt.Printf("BFV Inner Product Correct? %t\n", bfvRes)

	fmt.Println()
	fmt.Println("********************************************************************")
	fmt.Println()

	// Convert to float and add small decimals like C++ example
	asDouble := make([]float64, len(vec))
	for i, v := range vec {
		asDouble[i] = float64(v) + (float64(v) / 100.0)
	}

	fmt.Println("--- CKKS Inner Product ---")
	ckksRes := innerProductCKKS(asDouble)
	fmt.Printf("CKKS Inner Product Correct? %t\n", ckksRes)
}
