package openfhe

import (
	"math"
	"testing"
)

func mustT(t *testing.T, err error, where string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", where, err)
	}
}

func setupCKKSBootstrapContext(t *testing.T) (*CryptoContext, *KeyPair, uint32) {
	t.Helper()

	levelBudget := []uint32{4, 4}
	secretKeyDist := SecretKeyUniformTernary

	params := NewParamsCKKSRNS()
	params.SetSecretKeyDist(secretKeyDist)
	params.SetSecurityLevel(HEStdNotSet)     // critical for small N
	params.SetRingDim(uint64(1 << 12))       // N=4096 (slots=N/2)
	params.SetScalingTechnique(FLEXIBLEAUTO) // Python picks FLEXIBLEAUTO on 64-bit
	params.SetScalingModSize(59)
	params.SetFirstModSize(60)

	// depth = levelsAfter + GetBootstrapDepth(levelBudget, skd)
	levelsAfter := uint32(10)
	bootDepth := GetBootstrapDepth(levelBudget, secretKeyDist)
	params.SetMultiplicativeDepth(int(levelsAfter + bootDepth))

	cc := NewCryptoContextCKKS(params)
	cc.Enable(PKE)
	cc.Enable(KEYSWITCH)
	cc.Enable(LEVELEDSHE)
	cc.Enable(ADVANCEDSHE)
	cc.Enable(FHE)

	N := cc.GetRingDimension()
	if N != 1<<12 {
		t.Fatalf("unexpected ring dimension: got %d, want %d", N, 1<<12)
	}
	slots := uint32(N / 2)

	// Setup -> keys -> bootstrap keys
	mustT(t, cc.EvalBootstrapSetupSimple(levelBudget), "EvalBootstrapSetupSimple")

	kp := cc.KeyGen()
	cc.EvalMultKeyGen(kp)
	// Rotation keys not strictly required for this simple test, but safe to omit/add as desired.

	mustT(t, cc.EvalBootstrapKeyGen(kp, slots), "EvalBootstrapKeyGen")

	return cc, kp, slots
}

// Test 1: Bootstrap a ciphertext without prior arithmetic.
// Expect the output ~ input (small error), since we didn’t consume levels beforehand.
func TestCKKSBootstrap_SimpleRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CKKS bootstrapping test in -short mode")
	}

	cc, kp, _ := setupCKKSBootstrapContext(t)

	in := []float64{0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0}
	pt := cc.MakeCKKSPackedPlaintext(in)
	pt.SetLength(len(in))

	ct := cc.Encrypt(kp, pt)

	ctB, err := cc.EvalBootstrap(ct)
	mustT(t, err, "EvalBootstrap")

	ptOut := cc.Decrypt(kp, ctB)
	ptOut.SetLength(len(in))
	got := ptOut.GetRealPackedValue()

	tol := 0.02
	if !slicesApproxEqual(got[:len(in)], in, tol) {
		t.Fatalf("CKKS bootstrap roundtrip mismatch.\nwant ~%v\ngot  %v", in, got[:len(in)])
	}
}

// Test 2: Burn levels (v -> v^8 via three squarings) then bootstrap.
// After bootstrapping, the result should be close to v^8.
func TestCKKSBootstrap_AfterArithmetic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CKKS bootstrapping test in -short mode")
	}

	cc, kp, _ := setupCKKSBootstrapContext(t)

	in := []float64{0.25, 0.5, 0.75, 1.0, 2.0}
	want := make([]float64, len(in))
	for i, v := range in {
		want[i] = math.Pow(v, 8) // what we’ll compute via squarings
	}

	pt := cc.MakeCKKSPackedPlaintext(in)
	pt.SetLength(len(in))
	ct := cc.Encrypt(kp, pt)

	// v -> v^2 -> v^4 -> v^8, with rescale after each mult
	ct1 := cc.EvalMult(ct, ct)
	ct1 = cc.Rescale(ct1)
	ct2 := cc.EvalMult(ct1, ct1)
	ct2 = cc.Rescale(ct2)
	ct3 := cc.EvalMult(ct2, ct2)
	ct3 = cc.Rescale(ct3)

	ctB, err := cc.EvalBootstrap(ct3)
	mustT(t, err, "EvalBootstrap")

	ptOut := cc.Decrypt(kp, ctB)
	ptOut.SetLength(len(in))
	got := ptOut.GetRealPackedValue()

	tol := 0.02 // bootstrapping is approximate; loosen if needed
	if !slicesApproxEqual(got[:len(want)], want, tol) {
		t.Fatalf("CKKS bootstrap after arithmetic mismatch.\nwant ~%v\ngot  %v", want, got[:len(want)])
	}
}
