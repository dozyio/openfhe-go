package main

import (
	"fmt"
	"log"
	"math"

	"github.com/dozyio/openfhe-go/openfhe"
)

func must(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}

func approxEqual(a, b []float64, tol float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if math.Abs(a[i]-b[i]) > tol {
			return false
		}
	}
	return true
}

func main() {
	fmt.Println("--- Go simple-ckks-bootstrapping (simple setup) ---")

	params, err := openfhe.NewParamsCKKSRNS()
	must(err, "NewParamsCKKSRNS")
	defer params.Close()

	must(params.SetSecretKeyDist(openfhe.SecretKeyUniformTernary), "SetSecretKeyDist")
	must(params.SetSecurityLevel(openfhe.HEStdNotSet), "SetSecurityLevel") // important with small N
	must(params.SetRingDim(uint64(1<<12)), "SetRingDim")                   // 4096

	// 64-bit typical path (Python does FLEXIBLEAUTO / 59 / 60)
	must(params.SetScalingTechnique(openfhe.FLEXIBLEAUTO), "SetScalingTechnique")
	must(params.SetScalingModSize(59), "SetScalingModSize")
	must(params.SetFirstModSize(60), "SetFirstModSize")

	// depth = levelsAfter + GetBootstrapDepth(levelBudget, skd)
	levelBudget := []uint32{4, 4}
	bootstrapDepth := openfhe.GetBootstrapDepth(levelBudget, openfhe.SecretKeyUniformTernary) // tiny helper wrapper
	levelsAfter := uint32(10)
	must(params.SetMultiplicativeDepth(int(levelsAfter+bootstrapDepth)), "SetMultiplicativeDepth")

	// === 2) Context & enable ===
	cc, err := openfhe.NewCryptoContextCKKS(params)
	must(err, "NewCryptoContextCKKS")
	defer cc.Close()

	must(cc.Enable(openfhe.PKE), "Enable PKE")
	must(cc.Enable(openfhe.KEYSWITCH), "Enable KEYSWITCH")
	must(cc.Enable(openfhe.LEVELEDSHE), "Enable LEVELEDSHE")
	must(cc.Enable(openfhe.ADVANCEDSHE), "Enable ADVANCEDSHE")
	must(cc.Enable(openfhe.FHE), "Enable FHE")

	N := cc.GetRingDimension()
	slots := uint32(N / 2)
	fmt.Printf("CKKS ring dimension %d (slots=%d)\n", N, slots)

	must(cc.EvalBootstrapSetupSimple(levelBudget), "bootstrap setup")

	kp, err := cc.KeyGen()
	must(err, "KeyGen")
	defer kp.Close()

	must(cc.EvalMultKeyGen(kp), "EvalMultKeyGen") // relinearization keys
	must(cc.EvalBootstrapKeyGen(kp, slots), "bootstrap keygen")

	// === 5) Encode, encrypt, bootstrap ===
	x := []float64{0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0}
	pt, err := cc.MakeCKKSPackedPlaintext(x)
	must(err, "MakeCKKSPackedPlaintext")
	defer pt.Close()

	must(pt.SetLength(len(x)), "SetLength")

	ct, err := cc.Encrypt(kp, pt)
	must(err, "Encrypt")
	defer ct.Close()

	ctB, err := cc.EvalBootstrap(ct)
	must(err, "bootstrap")
	defer ctB.Close()

	out, err := cc.Decrypt(kp, ctB)
	must(err, "Decrypt")
	defer out.Close()

	must(out.SetLength(len(x)), "SetLength")
	got, err := out.GetRealPackedValue()
	must(err, "GetRealPackedValue")

	if approxEqual(got[:len(x)], x, 0.02) {
		fmt.Println("Bootstrap OK (values ~ input).")
	} else {
		fmt.Printf("Bootstrap result differs:\n in:  %v\n out: %v\n", x, got[:len(x)])
	}
}
