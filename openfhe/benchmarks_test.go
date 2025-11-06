package openfhe

import (
	"testing"
)

// BFV Benchmarks

func BenchmarkBFVContextSetup(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc, keys := setupBFVContextAndKeys(&testing.T{})
		cc.Close()
		keys.Close()
	}
}

func BenchmarkBFVEncrypt(b *testing.B) {
	cc, keys := setupBFVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt, _ := cc.MakePackedPlaintext(vec)
	defer pt.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, _ := cc.Encrypt(keys, pt)
		ct.Close()
	}
}

func BenchmarkBFVDecrypt(b *testing.B) {
	cc, keys := setupBFVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt, _ := cc.MakePackedPlaintext(vec)
	defer pt.Close()

	ct, _ := cc.Encrypt(keys, pt)
	defer ct.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ptDec, _ := cc.Decrypt(keys, ct)
		ptDec.Close()
	}
}

func BenchmarkBFVAdd(b *testing.B) {
	cc, keys := setupBFVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt, _ := cc.MakePackedPlaintext(vec)
	defer pt.Close()

	ct1, _ := cc.Encrypt(keys, pt)
	defer ct1.Close()
	ct2, _ := cc.Encrypt(keys, pt)
	defer ct2.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctAdd, _ := cc.EvalAdd(ct1, ct2)
		ctAdd.Close()
	}
}

func BenchmarkBFVMult(b *testing.B) {
	cc, keys := setupBFVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt, _ := cc.MakePackedPlaintext(vec)
	defer pt.Close()

	ct1, _ := cc.Encrypt(keys, pt)
	defer ct1.Close()
	ct2, _ := cc.Encrypt(keys, pt)
	defer ct2.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctMult, _ := cc.EvalMult(ct1, ct2)
		ctMult.Close()
	}
}

func BenchmarkBFVRotate(b *testing.B) {
	cc, keys := setupBFVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	_ = cc.EvalRotateKeyGen(keys, []int32{1})

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt, _ := cc.MakePackedPlaintext(vec)
	defer pt.Close()

	ct, _ := cc.Encrypt(keys, pt)
	defer ct.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctRot, _ := cc.EvalRotate(ct, 1)
		ctRot.Close()
	}
}

// BGV Benchmarks

func BenchmarkBGVContextSetup(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc, keys := setupBGVContextAndKeys(&testing.T{})
		cc.Close()
		keys.Close()
	}
}

func BenchmarkBGVEncrypt(b *testing.B) {
	cc, keys := setupBGVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt, _ := cc.MakePackedPlaintext(vec)
	defer pt.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, _ := cc.Encrypt(keys, pt)
		ct.Close()
	}
}

func BenchmarkBGVAdd(b *testing.B) {
	cc, keys := setupBGVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt, _ := cc.MakePackedPlaintext(vec)
	defer pt.Close()

	ct1, _ := cc.Encrypt(keys, pt)
	defer ct1.Close()
	ct2, _ := cc.Encrypt(keys, pt)
	defer ct2.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctAdd, _ := cc.EvalAdd(ct1, ct2)
		ctAdd.Close()
	}
}

func BenchmarkBGVMult(b *testing.B) {
	cc, keys := setupBGVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt, _ := cc.MakePackedPlaintext(vec)
	defer pt.Close()

	ct1, _ := cc.Encrypt(keys, pt)
	defer ct1.Close()
	ct2, _ := cc.Encrypt(keys, pt)
	defer ct2.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctMult, _ := cc.EvalMult(ct1, ct2)
		ctMult.Close()
	}
}

// CKKS Benchmarks

func BenchmarkCKKSContextSetup(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc, keys := setupCKKSContextAndKeys(&testing.T{})
		cc.Close()
		keys.Close()
	}
}

func BenchmarkCKKSEncrypt(b *testing.B) {
	cc, keys := setupCKKSContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	pt, _ := cc.MakeCKKSPackedPlaintext(vec)
	defer pt.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, _ := cc.Encrypt(keys, pt)
		ct.Close()
	}
}

func BenchmarkCKKSDecrypt(b *testing.B) {
	cc, keys := setupCKKSContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	pt, _ := cc.MakeCKKSPackedPlaintext(vec)
	defer pt.Close()

	ct, _ := cc.Encrypt(keys, pt)
	defer ct.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ptDec, _ := cc.Decrypt(keys, ct)
		ptDec.Close()
	}
}

func BenchmarkCKKSAdd(b *testing.B) {
	cc, keys := setupCKKSContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	pt, _ := cc.MakeCKKSPackedPlaintext(vec)
	defer pt.Close()

	ct1, _ := cc.Encrypt(keys, pt)
	defer ct1.Close()
	ct2, _ := cc.Encrypt(keys, pt)
	defer ct2.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctAdd, _ := cc.EvalAdd(ct1, ct2)
		ctAdd.Close()
	}
}

func BenchmarkCKKSMult(b *testing.B) {
	cc, keys := setupCKKSContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	pt, _ := cc.MakeCKKSPackedPlaintext(vec)
	defer pt.Close()

	ct1, _ := cc.Encrypt(keys, pt)
	defer ct1.Close()
	ct2, _ := cc.Encrypt(keys, pt)
	defer ct2.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctMult, _ := cc.EvalMult(ct1, ct2)
		ctMult.Close()
	}
}

func BenchmarkCKKSRescale(b *testing.B) {
	cc, keys := setupCKKSContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	pt, _ := cc.MakeCKKSPackedPlaintext(vec)
	defer pt.Close()

	ct1, _ := cc.Encrypt(keys, pt)
	defer ct1.Close()
	ct2, _ := cc.Encrypt(keys, pt)
	defer ct2.Close()

	ctMult, _ := cc.EvalMult(ct1, ct2)
	defer ctMult.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctRescaled, _ := cc.Rescale(ctMult)
		ctRescaled.Close()
	}
}

// BinFHE Benchmarks

func BenchmarkBinFHEContextSetup(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc, _ := NewBinFHEContext()
		_ = cc.GenerateBinFHEContext(STD128, GINX)
		cc.Close()
	}
}

func BenchmarkBinFHEEncrypt(b *testing.B) {
	cc, _ := NewBinFHEContext()
	defer cc.Close()
	_ = cc.GenerateBinFHEContext(STD128, GINX)

	sk, _ := cc.KeyGen()
	defer sk.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, _ := cc.Encrypt(sk, 1)
		ct.Close()
	}
}

func BenchmarkBinFHEDecrypt(b *testing.B) {
	cc, _ := NewBinFHEContext()
	defer cc.Close()
	_ = cc.GenerateBinFHEContext(STD128, GINX)

	sk, _ := cc.KeyGen()
	defer sk.Close()

	ct, _ := cc.Encrypt(sk, 1)
	defer ct.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cc.Decrypt(sk, ct)
	}
}

func BenchmarkBinFHEEvalAND(b *testing.B) {
	cc, _ := NewBinFHEContext()
	defer cc.Close()
	_ = cc.GenerateBinFHEContext(STD128, GINX)

	sk, _ := cc.KeyGen()
	defer sk.Close()
	_ = cc.BTKeyGen(sk)

	ct1, _ := cc.Encrypt(sk, 1)
	defer ct1.Close()
	ct2, _ := cc.Encrypt(sk, 1)
	defer ct2.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctAnd, _ := cc.EvalBinGate(AND, ct1, ct2)
		ctAnd.Close()
	}
}

func BenchmarkBinFHEEvalNOT(b *testing.B) {
	cc, _ := NewBinFHEContext()
	defer cc.Close()
	_ = cc.GenerateBinFHEContext(STD128, GINX)

	sk, _ := cc.KeyGen()
	defer sk.Close()
	_ = cc.BTKeyGen(sk)

	ct, _ := cc.Encrypt(sk, 1)
	defer ct.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctNot, _ := cc.EvalNOT(ct)
		ctNot.Close()
	}
}

// Serialization Benchmarks

func BenchmarkSerializeCryptoContext(b *testing.B) {
	cc, keys := setupBFVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SerializeCryptoContextToBytes(cc)
	}
}

func BenchmarkDeserializeCryptoContext(b *testing.B) {
	cc, keys := setupBFVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	serialized, _ := SerializeCryptoContextToBytes(cc)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccLoaded := DeserializeCryptoContextFromBytes(serialized)
		if ccLoaded != nil {
			ccLoaded.Close()
		}
	}
}

func BenchmarkSerializeCiphertext(b *testing.B) {
	cc, keys := setupBFVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt, _ := cc.MakePackedPlaintext(vec)
	defer pt.Close()

	ct, _ := cc.Encrypt(keys, pt)
	defer ct.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SerializeCiphertextToBytes(ct)
	}
}

func BenchmarkDeserializeCiphertext(b *testing.B) {
	cc, keys := setupBFVContextAndKeys(&testing.T{})
	defer cc.Close()
	defer keys.Close()

	vec := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	pt, _ := cc.MakePackedPlaintext(vec)
	defer pt.Close()

	ct, _ := cc.Encrypt(keys, pt)
	defer ct.Close()

	serialized, _ := SerializeCiphertextToBytes(ct)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctLoaded := DeserializeCiphertextFromBytes(serialized)
		if ctLoaded != nil {
			ctLoaded.Close()
		}
	}
}
