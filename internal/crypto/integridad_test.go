package crypto

import (
	"os"
	"testing"
)

func TestManipulacionDeArchivo(t *testing.T) {
	dirTemp := t.TempDir()
	rutas := RutasPorDefecto(dirTemp)

	cifradoOriginal := []byte("esto es un log cifrado falso, pero firmado")
	nonceOriginal := []byte("nonce1234567")

	publica, privada, _ := GenerarClavesEd25519()

	hashCifrado, _ := GuardarArtefactos(rutas, cifradoOriginal, []byte("claveFalsa32bytes..."), nonceOriginal)
	GuardarManifiestoYFirma(rutas, hashCifrado, nonceOriginal, privada)

	// 1. Todo está bien
	esValida, _ := VerificarFirmaAntesDeDescifrar(rutas, publica)
	if !esValida {
		t.Errorf("La firma original debería ser válida")
	}

	// 2. ATAQUE: Modificamos SOLO el log.enc, dejamos el manifiesto intacto
	datosManipulados := []byte("esto es un log HACKEADO")
	os.WriteFile(rutas.Cifrado, datosManipulados, 0o600)

	// 3. La verificación debe fallar porque el hash no coincide
	esValidaDespuesDelAtaque, _ := VerificarFirmaAntesDeDescifrar(rutas, publica)
	if esValidaDespuesDelAtaque {
		t.Errorf("¡PELIGRO! El sistema no detectó la manipulación de log.enc")
	} else {
		t.Log("✅ ÉXITO: El sistema detectó que log.enc fue alterado y rechazó la firma.")
	}
}
