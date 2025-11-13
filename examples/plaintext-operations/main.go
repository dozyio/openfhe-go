package main

import (
	"fmt"
	"log"

	"github.com/dozyio/openfhe-go/openfhe"
)

func checkErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

func main() {
	fmt.Println("=== Plaintext Operations Example ===")
	fmt.Println()

	// ============================================
	// BFV Example
	// ============================================
	fmt.Println("--- BFV (Integers) ---")

	params, err := openfhe.NewParamsBFVrns()
	checkErr(err, "NewParamsBFVrns")
	defer params.Close()

	checkErr(params.SetPlaintextModulus(65537), "SetPlaintextModulus")
	checkErr(params.SetMultiplicativeDepth(2), "SetMultiplicativeDepth")

	cc, err := openfhe.NewCryptoContextBFV(params)
	checkErr(err, "NewCryptoContextBFV")
	defer cc.Close()

	checkErr(cc.Enable(openfhe.PKE), "Enable PKE")
	checkErr(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	checkErr(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	checkErr(err, "KeyGen")
	defer keys.Close()

	checkErr(cc.EvalMultKeyGen(keys), "EvalMultKeyGen")

	// Encode and encrypt
	vec1 := []int64{1, 2, 3, 4, 5, 6, 7, 8}
	vec2 := []int64{10, 20, 30, 40, 50, 60, 70, 80}

	pt1, err := cc.MakePackedPlaintext(vec1)
	checkErr(err, "MakePackedPlaintext pt1")
	defer pt1.Close()

	pt2, err := cc.MakePackedPlaintext(vec2)
	checkErr(err, "MakePackedPlaintext pt2")
	defer pt2.Close()

	ct1, err := cc.Encrypt(keys, pt1)
	checkErr(err, "Encrypt ct1")
	defer ct1.Close()

	// EvalAddPlain
	ctAddPlain, err := cc.EvalAddPlain(ct1, pt2)
	checkErr(err, "EvalAddPlain")
	defer ctAddPlain.Close()

	// EvalSubPlain
	ctSubPlain, err := cc.EvalSubPlain(ct1, pt2)
	checkErr(err, "EvalSubPlain")
	defer ctSubPlain.Close()

	// EvalMultPlain
	ctMultPlain, err := cc.EvalMultPlain(ct1, pt2)
	checkErr(err, "EvalMultPlain")
	defer ctMultPlain.Close()

	// Decrypt and print results
	ptAddResult, err := cc.Decrypt(keys, ctAddPlain)
	checkErr(err, "Decrypt add")
	defer ptAddResult.Close()

	ptSubResult, err := cc.Decrypt(keys, ctSubPlain)
	checkErr(err, "Decrypt sub")
	defer ptSubResult.Close()

	ptMultResult, err := cc.Decrypt(keys, ctMultPlain)
	checkErr(err, "Decrypt mult")
	defer ptMultResult.Close()

	valAdd, err := ptAddResult.GetPackedValue()
	checkErr(err, "GetPackedValue add")

	valSub, err := ptSubResult.GetPackedValue()
	checkErr(err, "GetPackedValue sub")

	valMult, err := ptMultResult.GetPackedValue()
	checkErr(err, "GetPackedValue mult")

	fmt.Printf("x1       = %v\n", vec1)
	fmt.Printf("x2       = %v\n", vec2)
	fmt.Printf("x1 + x2  = %v\n", valAdd[:len(vec1)])
	fmt.Printf("x1 - x2  = %v\n", valSub[:len(vec1)])
	fmt.Printf("x1 * x2  = %v\n", valMult[:len(vec1)])

	// ============================================
	// CKKS Example
	// ============================================
	fmt.Println()
	fmt.Println("--- CKKS (Real Numbers) ---")

	ckksParams, err := openfhe.NewParamsCKKSRNS()
	checkErr(err, "NewParamsCKKSRNS")
	defer ckksParams.Close()

	checkErr(ckksParams.SetMultiplicativeDepth(3), "SetMultiplicativeDepth")
	checkErr(ckksParams.SetScalingModSize(50), "SetScalingModSize")
	checkErr(ckksParams.SetBatchSize(8), "SetBatchSize")

	ckksCC, err := openfhe.NewCryptoContextCKKS(ckksParams)
	checkErr(err, "NewCryptoContextCKKS")
	defer ckksCC.Close()

	checkErr(ckksCC.Enable(openfhe.PKE), "Enable PKE")
	checkErr(ckksCC.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	checkErr(ckksCC.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")

	ckksKeys, err := ckksCC.KeyGen()
	checkErr(err, "CKKS KeyGen")
	defer ckksKeys.Close()

	checkErr(ckksCC.EvalMultKeyGen(ckksKeys), "CKKS EvalMultKeyGen")

	// Encode and encrypt
	vecReal1 := []float64{0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0}
	vecReal2 := []float64{0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0}

	ptReal1, err := ckksCC.MakeCKKSPackedPlaintext(vecReal1)
	checkErr(err, "MakeCKKSPackedPlaintext pt1")
	defer ptReal1.Close()

	ptReal2, err := ckksCC.MakeCKKSPackedPlaintext(vecReal2)
	checkErr(err, "MakeCKKSPackedPlaintext pt2")
	defer ptReal2.Close()

	ctReal1, err := ckksCC.Encrypt(ckksKeys, ptReal1)
	checkErr(err, "Encrypt ct1")
	defer ctReal1.Close()

	// EvalAddPlain
	ctRealAddPlain, err := ckksCC.EvalAddPlain(ctReal1, ptReal2)
	checkErr(err, "EvalAddPlain")
	defer ctRealAddPlain.Close()

	// EvalSubPlain
	ctRealSubPlain, err := ckksCC.EvalSubPlain(ctReal1, ptReal2)
	checkErr(err, "EvalSubPlain")
	defer ctRealSubPlain.Close()

	// EvalMultPlain
	ctRealMultPlain, err := ckksCC.EvalMultPlain(ctReal1, ptReal2)
	checkErr(err, "EvalMultPlain")
	defer ctRealMultPlain.Close()

	// Decrypt and print results
	ptRealAddResult, err := ckksCC.Decrypt(ckksKeys, ctRealAddPlain)
	checkErr(err, "Decrypt add")
	defer ptRealAddResult.Close()

	ptRealSubResult, err := ckksCC.Decrypt(ckksKeys, ctRealSubPlain)
	checkErr(err, "Decrypt sub")
	defer ptRealSubResult.Close()

	ptRealMultResult, err := ckksCC.Decrypt(ckksKeys, ctRealMultPlain)
	checkErr(err, "Decrypt mult")
	defer ptRealMultResult.Close()

	valRealAdd, err := ptRealAddResult.GetRealPackedValue()
	checkErr(err, "GetRealPackedValue add")

	valRealSub, err := ptRealSubResult.GetRealPackedValue()
	checkErr(err, "GetRealPackedValue sub")

	valRealMult, err := ptRealMultResult.GetRealPackedValue()
	checkErr(err, "GetRealPackedValue mult")

	fmt.Printf("x1       = %v\n", vecReal1)
	fmt.Printf("x2       = %v\n", vecReal2)
	fmt.Printf("x1 + x2  = %.4f\n", valRealAdd[:len(vecReal1)])
	fmt.Printf("x1 - x2  = %.4f\n", valRealSub[:len(vecReal1)])
	fmt.Printf("x1 * x2  = %.4f\n", valRealMult[:len(vecReal1)])
}
