package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Manifiesto define los metadatos protegidos por la firma.
type Manifiesto struct {
	Version        int    `json:"version"`
	AlgoritmoHash  string `json:"algoritmo_hash"`
	AlgoritmoFirma string `json:"algoritmo_firma"`
	Archivo        string `json:"archivo"`
	Hash           string `json:"hash"`
	Nonce          string `json:"nonce"`
}

// GenerarClavesEd25519 se conserva por compatibilidad; usa GenerarParClaves (firma.go).
func GenerarClavesEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return GenerarParClaves()
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

// VerificarFirmaManifiesto devuelve true si la firma es válida.
// Envuelve VerificarFirma (firma.go), que devuelve el motivo del fallo.
func VerificarFirmaManifiesto(manifiesto, firma []byte, publica ed25519.PublicKey) bool {
	return VerificarFirma(manifiesto, firma, publica) == nil
}

// GuardarFirma escribe la firma en un archivo binario (.sig)
func GuardarFirma(ruta string, firma []byte) error {
	return escribirArchivo(ruta, firma) // Reutilizamos la función de artefactos.go
}
