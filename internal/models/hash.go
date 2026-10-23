package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// CalcularHashPayload hashea solo el PayloadEvento (nunca incluye hash_payload).
func CalcularHashPayload(p PayloadEvento) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// VerificarHashPayload recalcula el hash y lo compara con el almacenado.
func (e Evento) VerificarHashPayload() (bool, error) {
	h, err := CalcularHashPayload(e.PayloadEvento)
	if err != nil {
		return false, err
	}
	return h == e.HashPayload, nil
}
