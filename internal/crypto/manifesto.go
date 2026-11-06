package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Manifiesto es la estructura exacta que acordamos en el plan de Leandro.
type Manifiesto struct {
	Version        int    `json:"version"`
	AlgoritmoHash  string `json:"algoritmo_hash"`
	AlgoritmoFirma string `json:"algoritmo_firma"`
	Archivo        string `json:"archivo"`
	Hash           string `json:"hash"`
	Nonce          string `json:"nonce"`
}

// GenerarClavesEd25519 crea el par de claves (privada y pública).
// La privada se usa para firmar y la pública para verificar.
func GenerarClavesEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generando claves Ed25519: %w", err)
	}
	return pub, priv, nil
}

// CrearManifiesto genera el JSON del manifiesto y lo devuelve como bytes.
func CrearManifiesto(archivo string, hashCifrado string, nonce []byte) ([]byte, error) {
	// Convertimos el nonce a Base64 para que sea legible en el JSON
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	manifiesto := Manifiesto{
		Version:        1,
		AlgoritmoHash:  "SHA-256",
		AlgoritmoFirma: "Ed25519",
		Archivo:        archivo,
		Hash:           hashCifrado,
		Nonce:          nonceB64,
	}

	bytesManifiesto, err := json.MarshalIndent(manifiesto, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error serializando manifiesto: %w", err)
	}
	return bytesManifiesto, nil
}

// FirmarManifiesto recibe los bytes del manifiesto y la clave privada,
// y devuelve la firma digital.
func FirmarManifiesto(manifiesto []byte, privada ed25519.PrivateKey) ([]byte, error) {
	firma := ed25519.Sign(privada, manifiesto)
	return firma, nil
}

// VerificarFirmaManifiesto comprueba que la firma coincide con el manifiesto
// y la clave pública. Devuelve true si todo está bien.
func VerificarFirmaManifiesto(manifiesto, firma []byte, publica ed25519.PublicKey) bool {
	return ed25519.Verify(publica, manifiesto, firma)
}

// GuardarFirma escribe la firma en un archivo binario (.sig)
func GuardarFirma(ruta string, firma []byte) error {
	return escribirArchivo(ruta, firma) // Reutilizamos la función de artefactos.go
}

// GuardarClaves escribe las claves en archivos separados para la demo.
func GuardarClaves(rutaPrivada, rutaPublica string, privada ed25519.PrivateKey, publica ed25519.PublicKey) error {
	if err := escribirArchivo(rutaPrivada, privada); err != nil {
		return fmt.Errorf("guardando clave privada: %w", err)
	}
	if err := escribirArchivo(rutaPublica, publica); err != nil {
		return fmt.Errorf("guardando clave pública: %w", err)
	}
	return nil
}

// CalcularHashSHA256 (auxiliar por si lo necesitas aquí, aunque ya existe en crypto.go)
// Lo dejo por si acaso, pero usaremos el que ya tienes.
func calcularHashLocal(datos []byte) string {
	hash := sha256.Sum256(datos)
	return hex.EncodeToString(hash[:])
}
