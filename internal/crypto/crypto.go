package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// Cifrar encripta el log y devuelve el cifrado, la clave y el nonce.
func Cifrar(plano []byte) (cifrado, clave, nonce []byte, err error) {
	// Generar una clave aleatoria de 32 bytes para AES-256.
	clave = make([]byte, 32)
	if _, err = rand.Read(clave); err != nil {
		return nil, nil, nil, fmt.Errorf("generando clave: %w", err)
	}

	// Crear el algoritmo AES.
	bloque, err := aes.NewCipher(clave)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creando AES: %w", err)
	}

	// Crear GCM, que cifra y autentica los datos.
	gcm, err := cipher.NewGCM(bloque)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creando GCM: %w", err)
	}

	// Generar un nonce aleatorio del tamaño requerido por GCM.
	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("generando nonce: %w", err)
	}

	// Cifrar el texto plano.
	cifrado = gcm.Seal(nil, nonce, plano, nil)

	return cifrado, clave, nonce, nil
}

// Descifrar recupera el texto plano original.
func Descifrar(cifrado, clave, nonce []byte) ([]byte, error) {
	bloque, err := aes.NewCipher(clave)
	if err != nil {
		return nil, fmt.Errorf("creando AES para descifrar: %w", err)
	}

	gcm, err := cipher.NewGCM(bloque)
	if err != nil {
		return nil, fmt.Errorf("creando GCM para descifrar: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce inválido: longitud esperada %d bytes", gcm.NonceSize())
	}

	plano, err := gcm.Open(nil, nonce, cifrado, nil)
	if err != nil {
		return nil, fmt.Errorf("descifrando o verificando autenticidad: %w", err)
	}

	return plano, nil
}

// HashSHA256 devuelve el hash en hexadecimal.
func HashSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
