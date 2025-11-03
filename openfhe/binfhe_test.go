package openfhe

import (
	"testing"
)

func TestBinFHEEvalNOT(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	err = cc.BTKeyGen(sk)
	mustT(t, err, "generating BT keys")

	// Test NOT(1) = 0
	ct1, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1.Close()

	ctNot1, err := cc.EvalNOT(ct1)
	mustT(t, err, "evaluating NOT(1)")
	defer ctNot1.Close()

	result, err := cc.Decrypt(sk, ctNot1)
	mustT(t, err, "decrypting NOT(1)")

	if result != 0 {
		t.Errorf("NOT(1) = %d, expected 0", result)
	}

	// Test NOT(0) = 1
	ct0, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0.Close()

	ctNot0, err := cc.EvalNOT(ct0)
	mustT(t, err, "evaluating NOT(0)")
	defer ctNot0.Close()

	result, err = cc.Decrypt(sk, ctNot0)
	mustT(t, err, "decrypting NOT(0)")

	if result != 1 {
		t.Errorf("NOT(0) = %d, expected 1", result)
	}
}

func TestBinFHEEvalNOTNilContext(t *testing.T) {
	cc := &BinFHEContext{}

	ct := &BinFHECiphertext{}
	_, err := cc.EvalNOT(ct)
	if err == nil {
		t.Error("Expected error for nil context, got nil")
	}
}

func TestBinFHEEvalNOTNilCiphertext(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	_, err = cc.EvalNOT(nil)
	if err == nil {
		t.Error("Expected error for nil ciphertext, got nil")
	}
}

func TestBinFHEEvalAND(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	err = cc.BTKeyGen(sk)
	mustT(t, err, "generating BT keys")

	// Test AND(1, 1) = 1
	ct1a, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1a.Close()

	ct1b, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1b.Close()

	ctAnd11, err := cc.EvalBinGate(AND, ct1a, ct1b)
	mustT(t, err, "evaluating AND(1,1)")
	defer ctAnd11.Close()

	result, err := cc.Decrypt(sk, ctAnd11)
	mustT(t, err, "decrypting AND(1,1)")

	if result != 1 {
		t.Errorf("AND(1,1) = %d, expected 1", result)
	}

	// Test AND(1, 0) = 0
	ct0a, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0a.Close()

	ctAnd10, err := cc.EvalBinGate(AND, ct1a, ct0a)
	mustT(t, err, "evaluating AND(1,0)")
	defer ctAnd10.Close()

	result, err = cc.Decrypt(sk, ctAnd10)
	mustT(t, err, "decrypting AND(1,0)")

	if result != 0 {
		t.Errorf("AND(1,0) = %d, expected 0", result)
	}

	// Test AND(0, 1) = 0
	ct0b, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0b.Close()

	ct1c, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1c.Close()

	ctAnd01, err := cc.EvalBinGate(AND, ct0b, ct1c)
	mustT(t, err, "evaluating AND(0,1)")
	defer ctAnd01.Close()

	result, err = cc.Decrypt(sk, ctAnd01)
	mustT(t, err, "decrypting AND(0,1)")

	if result != 0 {
		t.Errorf("AND(0,1) = %d, expected 0", result)
	}

	// Test AND(0, 0) = 0
	ct0c, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0c.Close()

	ct0d, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0d.Close()

	ctAnd00, err := cc.EvalBinGate(AND, ct0c, ct0d)
	mustT(t, err, "evaluating AND(0,0)")
	defer ctAnd00.Close()

	result, err = cc.Decrypt(sk, ctAnd00)
	mustT(t, err, "decrypting AND(0,0)")

	if result != 0 {
		t.Errorf("AND(0,0) = %d, expected 0", result)
	}
}

func TestBinFHEEvalANDNilContext(t *testing.T) {
	cc := &BinFHEContext{}

	ct1 := &BinFHECiphertext{}
	ct2 := &BinFHECiphertext{}
	_, err := cc.EvalBinGate(AND, ct1, ct2)
	if err == nil {
		t.Error("Expected error for nil context, got nil")
	}
}

func TestBinFHEEvalANDNilCiphertext(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	ct, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting")
	defer ct.Close()

	// Test nil first ciphertext
	_, err = cc.EvalBinGate(AND, nil, ct)
	if err == nil {
		t.Error("Expected error for nil first ciphertext, got nil")
	}

	// Test nil second ciphertext
	_, err = cc.EvalBinGate(AND, ct, nil)
	if err == nil {
		t.Error("Expected error for nil second ciphertext, got nil")
	}
}

func TestBinFHEEvalOR(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	err = cc.BTKeyGen(sk)
	mustT(t, err, "generating BT keys")

	// Test OR(1, 1) = 1
	ct1a, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1a.Close()

	ct1b, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1b.Close()

	ctOr11, err := cc.EvalBinGate(OR, ct1a, ct1b)
	mustT(t, err, "evaluating OR(1,1)")
	defer ctOr11.Close()

	result, err := cc.Decrypt(sk, ctOr11)
	mustT(t, err, "decrypting OR(1,1)")

	if result != 1 {
		t.Errorf("OR(1,1) = %d, expected 1", result)
	}

	// Test OR(1, 0) = 1
	ct0a, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0a.Close()

	ctOr10, err := cc.EvalBinGate(OR, ct1a, ct0a)
	mustT(t, err, "evaluating OR(1,0)")
	defer ctOr10.Close()

	result, err = cc.Decrypt(sk, ctOr10)
	mustT(t, err, "decrypting OR(1,0)")

	if result != 1 {
		t.Errorf("OR(1,0) = %d, expected 1", result)
	}

	// Test OR(0, 1) = 1
	ct0b, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0b.Close()

	ct1c, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1c.Close()

	ctOr01, err := cc.EvalBinGate(OR, ct0b, ct1c)
	mustT(t, err, "evaluating OR(0,1)")
	defer ctOr01.Close()

	result, err = cc.Decrypt(sk, ctOr01)
	mustT(t, err, "decrypting OR(0,1)")

	if result != 1 {
		t.Errorf("OR(0,1) = %d, expected 1", result)
	}

	// Test OR(0, 0) = 0
	ct0c, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0c.Close()

	ct0d, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0d.Close()

	ctOr00, err := cc.EvalBinGate(OR, ct0c, ct0d)
	mustT(t, err, "evaluating OR(0,0)")
	defer ctOr00.Close()

	result, err = cc.Decrypt(sk, ctOr00)
	mustT(t, err, "decrypting OR(0,0)")

	if result != 0 {
		t.Errorf("OR(0,0) = %d, expected 0", result)
	}
}

func TestBinFHEEvalORNilContext(t *testing.T) {
	cc := &BinFHEContext{}

	ct1 := &BinFHECiphertext{}
	ct2 := &BinFHECiphertext{}
	_, err := cc.EvalBinGate(OR, ct1, ct2)
	if err == nil {
		t.Error("Expected error for nil context, got nil")
	}
}

func TestBinFHEEvalORNilCiphertext(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	ct, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting")
	defer ct.Close()

	// Test nil first ciphertext
	_, err = cc.EvalBinGate(OR, nil, ct)
	if err == nil {
		t.Error("Expected error for nil first ciphertext, got nil")
	}

	// Test nil second ciphertext
	_, err = cc.EvalBinGate(OR, ct, nil)
	if err == nil {
		t.Error("Expected error for nil second ciphertext, got nil")
	}
}

func TestBinFHEEvalNAND(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	err = cc.BTKeyGen(sk)
	mustT(t, err, "generating BT keys")

	// Test NAND(1, 1) = 0
	ct1a, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1a.Close()

	ct1b, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1b.Close()

	ctNand11, err := cc.EvalBinGate(NAND, ct1a, ct1b)
	mustT(t, err, "evaluating NAND(1,1)")
	defer ctNand11.Close()

	result, err := cc.Decrypt(sk, ctNand11)
	mustT(t, err, "decrypting NAND(1,1)")

	if result != 0 {
		t.Errorf("NAND(1,1) = %d, expected 0", result)
	}

	// Test NAND(1, 0) = 1
	ct0a, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0a.Close()

	ctNand10, err := cc.EvalBinGate(NAND, ct1a, ct0a)
	mustT(t, err, "evaluating NAND(1,0)")
	defer ctNand10.Close()

	result, err = cc.Decrypt(sk, ctNand10)
	mustT(t, err, "decrypting NAND(1,0)")

	if result != 1 {
		t.Errorf("NAND(1,0) = %d, expected 1", result)
	}

	// Test NAND(0, 1) = 1
	ct0b, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0b.Close()

	ct1c, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1c.Close()

	ctNand01, err := cc.EvalBinGate(NAND, ct0b, ct1c)
	mustT(t, err, "evaluating NAND(0,1)")
	defer ctNand01.Close()

	result, err = cc.Decrypt(sk, ctNand01)
	mustT(t, err, "decrypting NAND(0,1)")

	if result != 1 {
		t.Errorf("NAND(0,1) = %d, expected 1", result)
	}

	// Test NAND(0, 0) = 1
	ct0c, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0c.Close()

	ct0d, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0d.Close()

	ctNand00, err := cc.EvalBinGate(NAND, ct0c, ct0d)
	mustT(t, err, "evaluating NAND(0,0)")
	defer ctNand00.Close()

	result, err = cc.Decrypt(sk, ctNand00)
	mustT(t, err, "decrypting NAND(0,0)")

	if result != 1 {
		t.Errorf("NAND(0,0) = %d, expected 1", result)
	}
}

func TestBinFHEEvalNANDNilContext(t *testing.T) {
	cc := &BinFHEContext{}

	ct1 := &BinFHECiphertext{}
	ct2 := &BinFHECiphertext{}
	_, err := cc.EvalBinGate(NAND, ct1, ct2)
	if err == nil {
		t.Error("Expected error for nil context, got nil")
	}
}

func TestBinFHEEvalNANDNilCiphertext(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	ct, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting")
	defer ct.Close()

	// Test nil first ciphertext
	_, err = cc.EvalBinGate(NAND, nil, ct)
	if err == nil {
		t.Error("Expected error for nil first ciphertext, got nil")
	}

	// Test nil second ciphertext
	_, err = cc.EvalBinGate(NAND, ct, nil)
	if err == nil {
		t.Error("Expected error for nil second ciphertext, got nil")
	}
}

func TestBinFHEEvalNOR(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	err = cc.BTKeyGen(sk)
	mustT(t, err, "generating BT keys")

	// Test NOR(1, 1) = 0
	ct1a, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1a.Close()

	ct1b, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1b.Close()

	ctNor11, err := cc.EvalBinGate(NOR, ct1a, ct1b)
	mustT(t, err, "evaluating NOR(1,1)")
	defer ctNor11.Close()

	result, err := cc.Decrypt(sk, ctNor11)
	mustT(t, err, "decrypting NOR(1,1)")

	if result != 0 {
		t.Errorf("NOR(1,1) = %d, expected 0", result)
	}

	// Test NOR(1, 0) = 0
	ct0a, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0a.Close()

	ctNor10, err := cc.EvalBinGate(NOR, ct1a, ct0a)
	mustT(t, err, "evaluating NOR(1,0)")
	defer ctNor10.Close()

	result, err = cc.Decrypt(sk, ctNor10)
	mustT(t, err, "decrypting NOR(1,0)")

	if result != 0 {
		t.Errorf("NOR(1,0) = %d, expected 0", result)
	}

	// Test NOR(0, 1) = 0
	ct0b, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0b.Close()

	ct1c, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1c.Close()

	ctNor01, err := cc.EvalBinGate(NOR, ct0b, ct1c)
	mustT(t, err, "evaluating NOR(0,1)")
	defer ctNor01.Close()

	result, err = cc.Decrypt(sk, ctNor01)
	mustT(t, err, "decrypting NOR(0,1)")

	if result != 0 {
		t.Errorf("NOR(0,1) = %d, expected 0", result)
	}

	// Test NOR(0, 0) = 1
	ct0c, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0c.Close()

	ct0d, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0d.Close()

	ctNor00, err := cc.EvalBinGate(NOR, ct0c, ct0d)
	mustT(t, err, "evaluating NOR(0,0)")
	defer ctNor00.Close()

	result, err = cc.Decrypt(sk, ctNor00)
	mustT(t, err, "decrypting NOR(0,0)")

	if result != 1 {
		t.Errorf("NOR(0,0) = %d, expected 1", result)
	}
}

func TestBinFHEEvalNORNilContext(t *testing.T) {
	cc := &BinFHEContext{}

	ct1 := &BinFHECiphertext{}
	ct2 := &BinFHECiphertext{}
	_, err := cc.EvalBinGate(NOR, ct1, ct2)
	if err == nil {
		t.Error("Expected error for nil context, got nil")
	}
}

func TestBinFHEEvalNORNilCiphertext(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	ct, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting")
	defer ct.Close()

	// Test nil first ciphertext
	_, err = cc.EvalBinGate(NOR, nil, ct)
	if err == nil {
		t.Error("Expected error for nil first ciphertext, got nil")
	}

	// Test nil second ciphertext
	_, err = cc.EvalBinGate(NOR, ct, nil)
	if err == nil {
		t.Error("Expected error for nil second ciphertext, got nil")
	}
}

func TestBinFHEEvalXOR(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	err = cc.BTKeyGen(sk)
	mustT(t, err, "generating BT keys")

	// Test XOR(1, 1) = 0
	ct1a, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1a.Close()

	ct1b, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1b.Close()

	ctXor11, err := cc.EvalBinGate(XOR, ct1a, ct1b)
	mustT(t, err, "evaluating XOR(1,1)")
	defer ctXor11.Close()

	result, err := cc.Decrypt(sk, ctXor11)
	mustT(t, err, "decrypting XOR(1,1)")

	if result != 0 {
		t.Errorf("XOR(1,1) = %d, expected 0", result)
	}

	// Test XOR(1, 0) = 1
	ct0a, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0a.Close()

	ctXor10, err := cc.EvalBinGate(XOR, ct1a, ct0a)
	mustT(t, err, "evaluating XOR(1,0)")
	defer ctXor10.Close()

	result, err = cc.Decrypt(sk, ctXor10)
	mustT(t, err, "decrypting XOR(1,0)")

	if result != 1 {
		t.Errorf("XOR(1,0) = %d, expected 1", result)
	}

	// Test XOR(0, 1) = 1
	ct0b, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0b.Close()

	ct1c, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1c.Close()

	ctXor01, err := cc.EvalBinGate(XOR, ct0b, ct1c)
	mustT(t, err, "evaluating XOR(0,1)")
	defer ctXor01.Close()

	result, err = cc.Decrypt(sk, ctXor01)
	mustT(t, err, "decrypting XOR(0,1)")

	if result != 1 {
		t.Errorf("XOR(0,1) = %d, expected 1", result)
	}

	// Test XOR(0, 0) = 0
	ct0c, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0c.Close()

	ct0d, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0d.Close()

	ctXor00, err := cc.EvalBinGate(XOR, ct0c, ct0d)
	mustT(t, err, "evaluating XOR(0,0)")
	defer ctXor00.Close()

	result, err = cc.Decrypt(sk, ctXor00)
	mustT(t, err, "decrypting XOR(0,0)")

	if result != 0 {
		t.Errorf("XOR(0,0) = %d, expected 0", result)
	}
}

func TestBinFHEEvalXORNilContext(t *testing.T) {
	cc := &BinFHEContext{}

	ct1 := &BinFHECiphertext{}
	ct2 := &BinFHECiphertext{}
	_, err := cc.EvalBinGate(XOR, ct1, ct2)
	if err == nil {
		t.Error("Expected error for nil context, got nil")
	}
}

func TestBinFHEEvalXORNilCiphertext(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	ct, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting")
	defer ct.Close()

	// Test nil first ciphertext
	_, err = cc.EvalBinGate(XOR, nil, ct)
	if err == nil {
		t.Error("Expected error for nil first ciphertext, got nil")
	}

	// Test nil second ciphertext
	_, err = cc.EvalBinGate(XOR, ct, nil)
	if err == nil {
		t.Error("Expected error for nil second ciphertext, got nil")
	}
}

func TestBinFHEEvalXNOR(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	err = cc.BTKeyGen(sk)
	mustT(t, err, "generating BT keys")

	// Test XNOR(1, 1) = 1
	ct1a, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1a.Close()

	ct1b, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1b.Close()

	ctXnor11, err := cc.EvalBinGate(XNOR, ct1a, ct1b)
	mustT(t, err, "evaluating XNOR(1,1)")
	defer ctXnor11.Close()

	result, err := cc.Decrypt(sk, ctXnor11)
	mustT(t, err, "decrypting XNOR(1,1)")

	if result != 1 {
		t.Errorf("XNOR(1,1) = %d, expected 1", result)
	}

	// Test XNOR(1, 0) = 0
	ct0a, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0a.Close()

	ctXnor10, err := cc.EvalBinGate(XNOR, ct1a, ct0a)
	mustT(t, err, "evaluating XNOR(1,0)")
	defer ctXnor10.Close()

	result, err = cc.Decrypt(sk, ctXnor10)
	mustT(t, err, "decrypting XNOR(1,0)")

	if result != 0 {
		t.Errorf("XNOR(1,0) = %d, expected 0", result)
	}

	// Test XNOR(0, 1) = 0
	ct0b, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0b.Close()

	ct1c, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting 1")
	defer ct1c.Close()

	ctXnor01, err := cc.EvalBinGate(XNOR, ct0b, ct1c)
	mustT(t, err, "evaluating XNOR(0,1)")
	defer ctXnor01.Close()

	result, err = cc.Decrypt(sk, ctXnor01)
	mustT(t, err, "decrypting XNOR(0,1)")

	if result != 0 {
		t.Errorf("XNOR(0,1) = %d, expected 0", result)
	}

	// Test XNOR(0, 0) = 1
	ct0c, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0c.Close()

	ct0d, err := cc.Encrypt(sk, 0)
	mustT(t, err, "encrypting 0")
	defer ct0d.Close()

	ctXnor00, err := cc.EvalBinGate(XNOR, ct0c, ct0d)
	mustT(t, err, "evaluating XNOR(0,0)")
	defer ctXnor00.Close()

	result, err = cc.Decrypt(sk, ctXnor00)
	mustT(t, err, "decrypting XNOR(0,0)")

	if result != 1 {
		t.Errorf("XNOR(0,0) = %d, expected 1", result)
	}
}

func TestBinFHEEvalXNORNilContext(t *testing.T) {
	cc := &BinFHEContext{}

	ct1 := &BinFHECiphertext{}
	ct2 := &BinFHECiphertext{}
	_, err := cc.EvalBinGate(XNOR, ct1, ct2)
	if err == nil {
		t.Error("Expected error for nil context, got nil")
	}
}

func TestBinFHEEvalXNORNilCiphertext(t *testing.T) {
	cc, err := NewBinFHEContext()
	mustT(t, err, "creating context")
	defer cc.Close()

	err = cc.GenerateBinFHEContext(STD128, GINX)
	mustT(t, err, "generating context")

	sk, err := cc.KeyGen()
	mustT(t, err, "generating key")
	defer sk.Close()

	ct, err := cc.Encrypt(sk, 1)
	mustT(t, err, "encrypting")
	defer ct.Close()

	// Test nil first ciphertext
	_, err = cc.EvalBinGate(XNOR, nil, ct)
	if err == nil {
		t.Error("Expected error for nil first ciphertext, got nil")
	}

	// Test nil second ciphertext
	_, err = cc.EvalBinGate(XNOR, ct, nil)
	if err == nil {
		t.Error("Expected error for nil second ciphertext, got nil")
	}
}
