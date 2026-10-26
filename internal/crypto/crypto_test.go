package crypto

import (
	"bytes"
	"testing"
)

func TestCifrarYDescifrar(t *testing.T) {
	original := []byte(`{"mensaje":"Hola CryptoNotas"}`)

	cifrado, clave, nonce, err := Cifrar(original)
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}

	if bytes.Equal(cifrado, original) {
		t.Fatal("el contenido cifrado no debería ser igual al original")
	}

	recuperado, err := Descifrar(cifrado, clave, nonce)
	if err != nil {
		t.Fatalf("Descifrar devolvió un error: %v", err)
	}

	if !bytes.Equal(recuperado, original) {
		t.Fatalf("el contenido recuperado no coincide: got %s, want %s",
			recuperado, original)
	}
}

func TestHashSHA256(t *testing.T) {
	hash := HashSHA256([]byte("abc"))
	const esperado = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	if hash != esperado {
		t.Fatalf("hash incorrecto: got %s, want %s", hash, esperado)
	}
}

func TestDescifrarDetectaAlteracion(t *testing.T) {
	original := []byte("contenido confidencial")

	cifrado, clave, nonce, err := Cifrar(original)
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}

	// Alterar un byte del contenido cifrado.
	cifrado[0] ^= 1

	_, err = Descifrar(cifrado, clave, nonce)
	if err == nil {
		t.Fatal("se esperaba un error al alterar el contenido cifrado")
	}
}
