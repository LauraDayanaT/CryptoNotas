package crypto

import "fmt"

// Cifrar encripta el log y devuelve el cifrado, la clave y el nonce.
func Cifrar(plano []byte) (cifrado, clave, nonce []byte, err error) {
	return nil, nil, nil, fmt.Errorf("crypto.Cifrar: no implementado todavía")
}

// Descifrar recupera el texto plano original.
func Descifrar(cifrado, clave, nonce []byte) ([]byte, error) {
	return nil, fmt.Errorf("crypto.Descifrar: no implementado todavía")
}

// HashSHA256 devuelve el hash en hexadecimal.
func HashSHA256(data []byte) string {
	return ""
}
