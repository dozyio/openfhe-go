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

	// === 1) Params (match Python) ===
	params := openfhe.NewParamsCKKSRNS()
	params.SetSecretKeyDist(openfhe.SecretKeyUniformTernary)
	params.SetSecurityLevel(openfhe.HEStdNotSet) // important with small N
	params.SetRingDim(uint64(1 << 12))           // 4096

	// 64-bit typical path (Python does FLEXIBLEAUTO / 59 / 60)
	params.SetScalingTechnique(openfhe.FLEXIBLEAUTO)
	params.SetScalingModSize(59)
	params.SetFirstModSize(60)

	// depth = levelsAfter + GetBootstrapDepth(levelBudget, skd)
	levelBudget := []uint32{4, 4}
	bootstrapDepth := openfhe.GetBootstrapDepth(levelBudget, openfhe.SecretKeyUniformTernary) // tiny helper wrapper
	levelsAfter := uint32(10)
	params.SetMultiplicativeDepth(int(levelsAfter + bootstrapDepth))

	// === 2) Context & enable ===
	cc := openfhe.NewCryptoContextCKKS(params)
	cc.Enable(openfhe.PKE)
	cc.Enable(openfhe.KEYSWITCH)
	cc.Enable(openfhe.LEVELEDSHE)
	cc.Enable(openfhe.ADVANCEDSHE)
	cc.Enable(openfhe.FHE)

	N := cc.GetRingDimension()
	slots := uint32(N / 2)
	fmt.Printf("CKKS ring dimension %d (slots=%d)\n", N, slots)

	// === 3) SIMPLE bootstrap setup (like Python) ===
	// NOTE: if your wrapper is named differently, adjust the call accordingly.
	must(cc.EvalBootstrapSetupSimple(levelBudget), "bootstrap setup")

	// === 4) Keys and bootstrap keys ===
	kp := cc.KeyGen()
	cc.EvalMultKeyGen(kp) // relinearization keys
	must(cc.EvalBootstrapKeyGen(kp, slots), "bootstrap keygen")

	// === 5) Encode, encrypt, bootstrap ===
	x := []float64{0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0}
	pt := cc.MakeCKKSPackedPlaintext(x)
	pt.SetLength(len(x))

	ct := cc.Encrypt(kp, pt)

	// No manual “burning levels” needed; the Python sample bootstraps directly.
	ctB, err := cc.EvalBootstrap(ct) // assuming your wrapper returns (*Ciphertext, error)
	must(err, "bootstrap")

	out := cc.Decrypt(kp, ctB)
	out.SetLength(len(x))
	got := out.GetRealPackedValue()

	// Python prints the result; we can quick-check it stayed near input (since we didn't do math before bootstrap).
	if approxEqual(got[:len(x)], x, 0.02) {
		fmt.Println("Bootstrap OK (values ~ input).")
	} else {
		fmt.Printf("Bootstrap result differs:\n in:  %v\n out: %v\n", x, got[:len(x)])
	}
}
