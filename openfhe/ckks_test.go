package openfhe

import (
	"math"
	"testing"
)

func setupCKKSBootstrapContext(t *testing.T) (*CryptoContext, *KeyPair, uint32) {
	t.Helper()

	levelBudget := []uint32{4, 4}
	secretKeyDist := SecretKeyUniformTernary

	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close() // Params can be closed after CC is created

	mustT(t, params.SetSecretKeyDist(secretKeyDist), "SetSecretKeyDist")
	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel") // critical for small N
	mustT(t, params.SetRingDim(uint64(1<<12)), "SetRingDim")           // N=4096 (slots=N/2)
	mustT(t, params.SetScalingTechnique(FLEXIBLEAUTO), "SetScalingTechnique")
	mustT(t, params.SetScalingModSize(59), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(60), "SetFirstModSize")

	// depth = levelsAfter + GetBootstrapDepth(levelBudget, skd)
	levelsAfter := uint32(10)
	bootDepth := GetBootstrapDepth(levelBudget, secretKeyDist)
	mustT(t, params.SetMultiplicativeDepth(int(levelsAfter+bootDepth)), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")
	mustT(t, cc.Enable(FHE), "Enable FHE")

	N := cc.GetRingDimension()
	if N != 1<<12 {
		t.Fatalf("unexpected ring dimension: got %d, want %d", N, 1<<12)
	}
	slots := uint32(N / 2)

	// Setup -> keys -> bootstrap keys
	mustT(t, cc.EvalBootstrapSetupSimple(levelBudget), "EvalBootstrapSetupSimple")

	kp, err := cc.KeyGen()
	mustT(t, err, "KeyGen")

	mustT(t, cc.EvalMultKeyGen(kp), "EvalMultKeyGen")
	// Rotation keys not strictly required for this simple test, but safe to omit/add as desired.

	mustT(t, cc.EvalBootstrapKeyGen(kp, slots), "EvalBootstrapKeyGen")

	return cc, kp, slots // Caller is responsible for Closing cc and kp
}

// Test 1: Bootstrap a ciphertext without prior arithmetic.
func TestCKKSBootstrap_SimpleRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CKKS bootstrapping test in -short mode")
	}

	cc, kp, _ := setupCKKSBootstrapContext(t)
	defer cc.Close()
	defer kp.Close()

	in := []float64{0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0}
	pt, err := cc.MakeCKKSPackedPlaintext(in)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer pt.Close()

	mustT(t, pt.SetLength(len(in)), "SetLength")

	ct, err := cc.Encrypt(kp, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	ctB, err := cc.EvalBootstrap(ct)
	mustT(t, err, "EvalBootstrap")
	defer ctB.Close()

	ptOut, err := cc.Decrypt(kp, ctB)
	mustT(t, err, "Decrypt")
	defer ptOut.Close()

	mustT(t, ptOut.SetLength(len(in)), "SetLength")
	got, err := ptOut.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	tol := 0.02
	if !slicesApproxEqual(got[:len(in)], in, tol) {
		t.Fatalf("CKKS bootstrap roundtrip mismatch.\nwant ~%v\ngot  %v", in, got[:len(in)])
	}
}

// Test 2: Burn levels (v -> v^8 via three squarings) then bootstrap.
func TestCKKSBootstrap_AfterArithmetic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CKKS bootstrapping test in -short mode")
	}

	cc, kp, _ := setupCKKSBootstrapContext(t)
	defer cc.Close()
	defer kp.Close()

	in := []float64{0.25, 0.5, 0.75, 1.0, 2.0}
	want := make([]float64, len(in))
	for i, v := range in {
		want[i] = math.Pow(v, 8) // what we’ll compute via squarings
	}

	pt, err := cc.MakeCKKSPackedPlaintext(in)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer pt.Close()

	mustT(t, pt.SetLength(len(in)), "SetLength")
	ct, err := cc.Encrypt(kp, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	// v -> v^2 -> v^4 -> v^8, with rescale after each mult
	ct1, err := cc.EvalMult(ct, ct)
	mustT(t, err, "EvalMult ct1")
	defer ct1.Close()
	ct1_r, err := cc.Rescale(ct1)
	mustT(t, err, "Rescale ct1_r")
	defer ct1_r.Close()

	ct2, err := cc.EvalMult(ct1_r, ct1_r)
	mustT(t, err, "EvalMult ct2")
	defer ct2.Close()
	ct2_r, err := cc.Rescale(ct2)
	mustT(t, err, "Rescale ct2_r")
	defer ct2_r.Close()

	ct3, err := cc.EvalMult(ct2_r, ct2_r)
	mustT(t, err, "EvalMult ct3")
	defer ct3.Close()
	ct3_r, err := cc.Rescale(ct3)
	mustT(t, err, "Rescale ct3_r")
	defer ct3_r.Close()

	ctB, err := cc.EvalBootstrap(ct3_r)
	mustT(t, err, "EvalBootstrap")
	defer ctB.Close()

	ptOut, err := cc.Decrypt(kp, ctB)
	mustT(t, err, "Decrypt")
	defer ptOut.Close()

	mustT(t, ptOut.SetLength(len(in)), "SetLength")
	got, err := ptOut.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	tol := 0.02 // bootstrapping is approximate; loosen if needed
	if !slicesApproxEqual(got[:len(want)], want, tol) {
		t.Fatalf("CKKS bootstrap after arithmetic mismatch.\nwant ~%v\ngot  %v", want, got[:len(want)])
	}
}
