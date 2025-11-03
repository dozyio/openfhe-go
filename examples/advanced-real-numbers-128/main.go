package main

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/dozyio/openfhe-go/openfhe"
)

func must(err error, context string) {
	if err != nil {
		log.Fatalf("%s: %v", context, err)
	}
}

func automaticRescaleDemo(scalTech int, techName string, scalingModSize int) {
	fmt.Printf("\n\n\n ===== %s Demo =============\n", techName)

	batchSize := 8
	parameters, err := openfhe.NewParamsCKKSRNS()
	must(err, "NewParamsCKKSRNS")
	defer parameters.Close()

	must(parameters.SetMultiplicativeDepth(6), "SetMultiplicativeDepth")
	must(parameters.SetScalingModSize(scalingModSize), "SetScalingModSize")
	must(parameters.SetScalingTechnique(scalTech), "SetScalingTechnique")
	must(parameters.SetBatchSize(batchSize), "SetBatchSize")

	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	must(err, "NewCryptoContextCKKS")
	defer cc.Close()

	fmt.Printf("CKKS scheme is using ring dimension %d\n\n", cc.GetRingDimension())

	must(cc.Enable(openfhe.PKE), "Enable PKE")
	must(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	must(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	must(err, "KeyGen")
	defer keys.Close()

	must(cc.EvalMultKeyGen(keys), "EvalMultKeyGen")

	// Input
	x := []float64{1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07}
	ptxt, err := cc.MakeCKKSPackedPlaintext(x)
	must(err, "MakeCKKSPackedPlaintext")
	defer ptxt.Close()

	fmt.Printf("Input x: %v\n", x)

	c, err := cc.Encrypt(keys, ptxt)
	must(err, "Encrypt")
	defer c.Close()

	// Computing f(x) = x^18 + x^9 + 1
	c2, err := cc.EvalMult(c, c) // x^2
	must(err, "EvalMult c^2")
	defer c2.Close()

	c4, err := cc.EvalMult(c2, c2) // x^4
	must(err, "EvalMult c^4")
	defer c4.Close()

	c8, err := cc.EvalMult(c4, c4) // x^8
	must(err, "EvalMult c^8")
	defer c8.Close()

	c16, err := cc.EvalMult(c8, c8) // x^16
	must(err, "EvalMult c^16")
	defer c16.Close()

	c9, err := cc.EvalMult(c8, c) // x^9
	must(err, "EvalMult c^9")
	defer c9.Close()

	c18, err := cc.EvalMult(c16, c2) // x^18
	must(err, "EvalMult c^18")
	defer c18.Close()

	cRes1, err := cc.EvalAdd(c18, c9)
	must(err, "EvalAdd c18+c9")
	defer cRes1.Close()

	result1, err := cc.Decrypt(keys, cRes1)
	must(err, "Decrypt result1")
	defer result1.Close()
	must(result1.SetLength(batchSize), "SetLength")

	result1Val, err := result1.GetRealPackedValue()
	must(err, "GetRealPackedValue result1")
	fmt.Printf("x^18 + x^9 = %v\n", result1Val[:batchSize])
}

func manualRescaleDemo() {
	fmt.Printf("\n\n\n ===== FixedManual Demo =============\n")

	batchSize := 8
	parameters, err := openfhe.NewParamsCKKSRNS()
	must(err, "NewParamsCKKSRNS")
	defer parameters.Close()

	// Use smaller scaling mod size for 64-bit compatibility
	scalingModSize := 50
	if openfhe.GetNativeInt() == 128 {
		scalingModSize = 89
	}

	must(parameters.SetMultiplicativeDepth(5), "SetMultiplicativeDepth")
	must(parameters.SetScalingModSize(scalingModSize), "SetScalingModSize")
	must(parameters.SetScalingTechnique(openfhe.FIXEDMANUAL), "SetScalingTechnique")
	must(parameters.SetBatchSize(batchSize), "SetBatchSize")

	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	must(err, "NewCryptoContextCKKS")
	defer cc.Close()

	fmt.Printf("CKKS scheme is using ring dimension %d\n\n", cc.GetRingDimension())

	must(cc.Enable(openfhe.PKE), "Enable PKE")
	must(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	must(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	must(err, "KeyGen")
	defer keys.Close()

	must(cc.EvalMultKeyGen(keys), "EvalMultKeyGen")

	// Input
	x := []float64{1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7}
	ptxt, err := cc.MakeCKKSPackedPlaintext(x)
	must(err, "MakeCKKSPackedPlaintext")
	defer ptxt.Close()

	fmt.Printf("Input x: %v\n", x)

	c, err := cc.Encrypt(keys, ptxt)
	must(err, "Encrypt")
	defer c.Close()

	// x^2
	c2Depth2, err := cc.EvalMult(c, c)
	must(err, "EvalMult c^2")
	defer c2Depth2.Close()

	c2Depth1, err := cc.Rescale(c2Depth2)
	must(err, "Rescale c^2")
	defer c2Depth1.Close()

	// x^4
	c4Depth2, err := cc.EvalMult(c2Depth1, c2Depth1)
	must(err, "EvalMult c^4")
	defer c4Depth2.Close()

	c4Depth1, err := cc.Rescale(c4Depth2)
	must(err, "Rescale c^4")
	defer c4Depth1.Close()

	// x^8
	c8Depth2, err := cc.EvalMult(c4Depth1, c4Depth1)
	must(err, "EvalMult c^8")
	defer c8Depth2.Close()

	c8Depth1, err := cc.Rescale(c8Depth2)
	must(err, "Rescale c^8")
	defer c8Depth1.Close()

	// x^16
	c16Depth2, err := cc.EvalMult(c8Depth1, c8Depth1)
	must(err, "EvalMult c^16")
	defer c16Depth2.Close()

	c16Depth1, err := cc.Rescale(c16Depth2)
	must(err, "Rescale c^16")
	defer c16Depth1.Close()

	// x^9
	c9Depth2, err := cc.EvalMult(c8Depth1, c)
	must(err, "EvalMult c^9")
	defer c9Depth2.Close()

	// x^18
	c18Depth2, err := cc.EvalMult(c16Depth1, c2Depth1)
	must(err, "EvalMult c^18")
	defer c18Depth2.Close()

	// Final result
	cResDepth2, err := cc.EvalAdd(c18Depth2, c9Depth2)
	must(err, "EvalAdd c18+c9")
	defer cResDepth2.Close()

	cResDepth1, err := cc.Rescale(cResDepth2)
	must(err, "Rescale final")
	defer cResDepth1.Close()

	result, err := cc.Decrypt(keys, cResDepth1)
	must(err, "Decrypt")
	defer result.Close()
	must(result.SetLength(batchSize), "SetLength")

	resultVal, err := result.GetRealPackedValue()
	must(err, "GetRealPackedValue")
	fmt.Printf("x^18 + x^9 = %v\n", resultVal[:batchSize])
}

func hybridKeySwitchingDemo(numDigits int) {
	fmt.Printf("\n\n\n ===== Hybrid Key Switching Demo (%d digits) =============\n", numDigits)

	batchSize := 8
	parameters, err := openfhe.NewParamsCKKSRNS()
	must(err, "NewParamsCKKSRNS")
	defer parameters.Close()

	must(parameters.SetMultiplicativeDepth(5), "SetMultiplicativeDepth")
	must(parameters.SetScalingModSize(89), "SetScalingModSize")
	must(parameters.SetBatchSize(batchSize), "SetBatchSize")
	must(parameters.SetScalingTechnique(openfhe.FIXEDAUTO), "SetScalingTechnique")
	must(parameters.SetNumLargeDigits(numDigits), "SetNumLargeDigits")

	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	must(err, "NewCryptoContextCKKS")
	defer cc.Close()

	fmt.Printf("CKKS scheme is using ring dimension %d\n", cc.GetRingDimension())
	fmt.Printf("- Using HYBRID key switching with %d digits\n\n", numDigits)

	must(cc.Enable(openfhe.PKE), "Enable PKE")
	must(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	must(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	must(err, "KeyGen")
	defer keys.Close()

	must(cc.EvalRotateKeyGen(keys, []int32{1, -2}), "EvalRotateKeyGen")

	// Input
	x := []float64{1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7}
	ptxt, err := cc.MakeCKKSPackedPlaintext(x)
	must(err, "MakeCKKSPackedPlaintext")
	defer ptxt.Close()

	fmt.Printf("Input x: %v\n", x)

	c, err := cc.Encrypt(keys, ptxt)
	must(err, "Encrypt")
	defer c.Close()

	start := time.Now()
	cRot1, err := cc.EvalRotate(c, 1)
	must(err, "EvalRotate 1")
	defer cRot1.Close()

	cRot2, err := cc.EvalRotate(cRot1, -2)
	must(err, "EvalRotate -2")
	defer cRot2.Close()
	elapsed := time.Since(start)

	result, err := cc.Decrypt(keys, cRot2)
	must(err, "Decrypt")
	defer result.Close()
	must(result.SetLength(batchSize), "SetLength")

	resultVal, err := result.GetRealPackedValue()
	must(err, "GetRealPackedValue")
	fmt.Printf("x rotate by -1 = %v\n", resultVal[:batchSize])
	fmt.Printf(" - 2 rotations with HYBRID (%d digits) took %.3f ms\n", numDigits, float64(elapsed.Microseconds())/1000.0)
}

func fastRotationDemo(useBV bool) {
	if useBV {
		fmt.Printf("\n\n\n ===== Fast Rotation Demo 2 (BV) =============\n")
	} else {
		fmt.Printf("\n\n\n ===== Fast Rotation Demo 1 =============\n")
	}

	batchSize := 8
	parameters, err := openfhe.NewParamsCKKSRNS()
	must(err, "NewParamsCKKSRNS")
	defer parameters.Close()

	must(parameters.SetMultiplicativeDepth(1), "SetMultiplicativeDepth")
	must(parameters.SetScalingModSize(89), "SetScalingModSize")
	must(parameters.SetBatchSize(batchSize), "SetBatchSize")
	must(parameters.SetScalingTechnique(openfhe.FIXEDAUTO), "SetScalingTechnique")

	if useBV {
		must(parameters.SetKeySwitchTechnique(openfhe.BV), "SetKeySwitchTechnique")
		digitSize := 10
		firstModSize := 100
		must(parameters.SetFirstModSize(firstModSize), "SetFirstModSize")
		must(parameters.SetDigitSize(digitSize), "SetDigitSize")
	}

	cc, err := openfhe.NewCryptoContextCKKS(parameters)
	must(err, "NewCryptoContextCKKS")
	defer cc.Close()

	N := cc.GetRingDimension()
	fmt.Printf("CKKS scheme is using ring dimension %d\n\n", N)

	must(cc.Enable(openfhe.PKE), "Enable PKE")
	must(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	must(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")

	keys, err := cc.KeyGen()
	must(err, "KeyGen")
	defer keys.Close()

	must(cc.EvalRotateKeyGen(keys, []int32{1, 2, 3, 4, 5, 6, 7}), "EvalRotateKeyGen")

	// Input
	x := []float64{0, 0, 0, 0, 0, 0, 0, 1}
	ptxt, err := cc.MakeCKKSPackedPlaintext(x)
	must(err, "MakeCKKSPackedPlaintext")
	defer ptxt.Close()

	fmt.Printf("Input x: %v\n", x)

	c, err := cc.Encrypt(keys, ptxt)
	must(err, "Encrypt")
	defer c.Close()

	// Regular rotations without hoisting
	start := time.Now()
	cRot1, err := cc.EvalRotate(c, 1)
	must(err, "EvalRotate 1")
	defer cRot1.Close()

	cRot2, err := cc.EvalRotate(c, 2)
	must(err, "EvalRotate 2")
	defer cRot2.Close()

	cRot3, err := cc.EvalRotate(c, 3)
	must(err, "EvalRotate 3")
	defer cRot3.Close()

	cRot4, err := cc.EvalRotate(c, 4)
	must(err, "EvalRotate 4")
	defer cRot4.Close()

	cRot5, err := cc.EvalRotate(c, 5)
	must(err, "EvalRotate 5")
	defer cRot5.Close()

	cRot6, err := cc.EvalRotate(c, 6)
	must(err, "EvalRotate 6")
	defer cRot6.Close()

	cRot7, err := cc.EvalRotate(c, 7)
	must(err, "EvalRotate 7")
	defer cRot7.Close()

	timeNoHoisting := time.Since(start)

	cResNoHoist, err := cc.EvalAdd(c, cRot1)
	must(err, "EvalAdd")
	defer cResNoHoist.Close()

	for _, ct := range []*openfhe.Ciphertext{cRot2, cRot3, cRot4, cRot5, cRot6, cRot7} {
		tmp, err := cc.EvalAdd(cResNoHoist, ct)
		must(err, "EvalAdd")
		cResNoHoist.Close()
		cResNoHoist = tmp
	}

	// M is the cyclotomic order
	M := uint32(2 * N)

	// Rotations with hoisting
	start = time.Now()
	cPrecomp, err := cc.EvalFastRotationPrecompute(c)
	must(err, "EvalFastRotationPrecompute")
	defer cPrecomp.Close()

	cRotFast1, err := cc.EvalFastRotation(c, 1, M, cPrecomp)
	must(err, "EvalFastRotation 1")
	defer cRotFast1.Close()

	cRotFast2, err := cc.EvalFastRotation(c, 2, M, cPrecomp)
	must(err, "EvalFastRotation 2")
	defer cRotFast2.Close()

	cRotFast3, err := cc.EvalFastRotation(c, 3, M, cPrecomp)
	must(err, "EvalFastRotation 3")
	defer cRotFast3.Close()

	cRotFast4, err := cc.EvalFastRotation(c, 4, M, cPrecomp)
	must(err, "EvalFastRotation 4")
	defer cRotFast4.Close()

	cRotFast5, err := cc.EvalFastRotation(c, 5, M, cPrecomp)
	must(err, "EvalFastRotation 5")
	defer cRotFast5.Close()

	cRotFast6, err := cc.EvalFastRotation(c, 6, M, cPrecomp)
	must(err, "EvalFastRotation 6")
	defer cRotFast6.Close()

	cRotFast7, err := cc.EvalFastRotation(c, 7, M, cPrecomp)
	must(err, "EvalFastRotation 7")
	defer cRotFast7.Close()

	timeHoisting := time.Since(start)

	cResHoist, err := cc.EvalAdd(c, cRotFast1)
	must(err, "EvalAdd")
	defer cResHoist.Close()

	for _, ct := range []*openfhe.Ciphertext{cRotFast2, cRotFast3, cRotFast4, cRotFast5, cRotFast6, cRotFast7} {
		tmp, err := cc.EvalAdd(cResHoist, ct)
		must(err, "EvalAdd")
		cResHoist.Close()
		cResHoist = tmp
	}

	resultNoHoist, err := cc.Decrypt(keys, cResNoHoist)
	must(err, "Decrypt no hoist")
	defer resultNoHoist.Close()
	must(resultNoHoist.SetLength(batchSize), "SetLength")

	resultNoHoistVal, err := resultNoHoist.GetRealPackedValue()
	must(err, "GetRealPackedValue")
	fmt.Printf("Result without hoisting: %v\n", resultNoHoistVal[:batchSize])
	fmt.Printf(" - 7 rotations without hoisting took %.3f ms\n", float64(timeNoHoisting.Microseconds())/1000.0)

	resultHoist, err := cc.Decrypt(keys, cResHoist)
	must(err, "Decrypt hoist")
	defer resultHoist.Close()
	must(resultHoist.SetLength(batchSize), "SetLength")

	resultHoistVal, err := resultHoist.GetRealPackedValue()
	must(err, "GetRealPackedValue")
	fmt.Printf("Result with hoisting: %v\n", resultHoistVal[:batchSize])
	fmt.Printf(" - 7 rotations with hoisting took %.3f ms\n", float64(timeHoisting.Microseconds())/1000.0)
}

func main() {
	nativeInt := openfhe.GetNativeInt()
	fmt.Printf("Native integer size: %d bits\n", nativeInt)

	if nativeInt == 128 {
		// 128-bit native integers allow larger scaling modulus
		automaticRescaleDemo(openfhe.FIXEDAUTO, "FixedAuto", 89)
		// Note: FLEXIBLEAUTO is not supported for 128-bit CKKS
		manualRescaleDemo()
		hybridKeySwitchingDemo(2)
		hybridKeySwitchingDemo(3)
		fastRotationDemo(false)
		fastRotationDemo(true)
	} else {
		fmt.Println("\nThis demo is designed for 128-bit CKKS.")
		fmt.Println("If you want to test it, please reinstall OpenFHE C++ with the flag -DNATIVE_SIZE=128,")
		fmt.Println("then rebuild openfhe-go.")
		fmt.Println("\nFor now, running a subset of demos with 64-bit native integers...\n")

		// Still run some demos to show functionality (with smaller scaling modulus for 64-bit)
		automaticRescaleDemo(openfhe.FIXEDAUTO, "FixedAuto", 50)
		manualRescaleDemo()
		fmt.Println("\n(Skipping advanced demos - they require 128-bit native integers for optimal performance)")
	}

	// Calculate and print expected values for verification
	fmt.Println("\n=== Verification ===")
	x := []float64{1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07}
	fmt.Println("For input x:", x)
	fmt.Println("Expected x^18 + x^9:")
	for i, val := range x {
		expected := math.Pow(val, 18) + math.Pow(val, 9)
		fmt.Printf("  x[%d]=%.2f: %.6f\n", i, val, expected)
	}
}
