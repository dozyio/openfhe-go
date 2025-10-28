package openfhe

import (
	"math"
	"testing"
)

func slicesEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func slicesApproxEqual(a, b []float64, tolerance float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if math.Abs(v-b[i]) > tolerance {
			return false
		}
	}
	return true
}

func mustT(t *testing.T, err error, where string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", where, err)
	}
}
