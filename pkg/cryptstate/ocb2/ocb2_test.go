package ocb2

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestTimes2(t *testing.T) {
	msg := [aes.BlockSize]byte{
		0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	}
	expected := [aes.BlockSize]byte{
		0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7b,
	}

	times2(msg[0:])
	if !bytes.Equal(msg[0:], expected[0:]) {
		t.Fatalf("times2 produces invalid output: %v, expected: %v", msg, expected)
	}
}

func TestTimes3(t *testing.T) {
	msg := [aes.BlockSize]byte{
		0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	}
	expected := [aes.BlockSize]byte{
		0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85,
	}

	times3(msg[0:])
	if !bytes.Equal(msg[0:], expected[0:]) {
		t.Errorf("times3 produces invalid output: %v, expected: %v", msg, expected)
	}
}

func TestZeros(t *testing.T) {
	var msg [aes.BlockSize]byte
	zeros(msg[0:])
	for i := 0; i < len(msg); i++ {
		if msg[i] != 0 {
			t.Fatalf("zeros does not zero slice.")
		}
	}
}

func TestXor(t *testing.T) {
	msg := [aes.BlockSize]byte{
		0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	}
	var out [aes.BlockSize]byte
	xor(out[0:], msg[0:], msg[0:])
	for i := 0; i < len(out); i++ {
		if out[i] != 0 {
			t.Fatalf("XOR broken")
		}
	}
}