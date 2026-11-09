package crypto

import (
	"os"
	"testing"
)

func TestAlteracionNonceFirmado(t *testing.T) {
	dir := t.TempDir()
	rutas := RutasPorDefecto(dir)

	// Crear un archivo cifrado de prueba.
	cifrado := []byte("contenido cifrado de prueba")
	clave := make([]byte, 32)
	nonce := make([]byte, 12)

	// Generar claves para firmar el manifiesto.
	publica, privada, err := GenerarClavesEd25519()
	if err != nil {
		t.Fatal(err)
	}

	// Guardar los artefactos.
	hash, err := GuardarArtefactos(rutas, cifrado, clave, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Crear y firmar el manifiesto.
	if err := GuardarManifiestoYFirma(rutas, hash, nonce, privada); err != nil {
		t.Fatal(err)
	}

	// Comprobar que inicialmente es válido.
	valida, err := VerificarFirmaAntesDeDescifrar(rutas, publica)
	if err != nil || !valida {
		t.Fatalf("el archivo original debería ser válido: %v", err)
	}

	// Simular una alteración del nonce.
	nonce[0] ^= 1

	if err := os.WriteFile(rutas.Nonce, nonce, 0600); err != nil {
		t.Fatal(err)
	}

	// La verificación debe rechazar la alteración.
	valida, err = VerificarFirmaAntesDeDescifrar(rutas, publica)
	if err != nil {
		t.Fatal(err)
	}

	if valida {
		t.Fatal("ERROR: se aceptó un nonce manipulado")
	}
}
