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

	publica, privada, err := GenerarClavesEd25519()
	if err != nil {
		t.Fatalf("Error generando claves: %v", err)
	}

	hashCifrado, err := GuardarArtefactos(rutas, cifradoOriginal, []byte("claveFalsa32bytes..."), nonceOriginal)
	if err != nil {
		t.Fatalf("Error guardando artefactos: %v", err)
	}

	err = GuardarManifiestoYFirma(rutas, hashCifrado, nonceOriginal, privada)
	if err != nil {
		t.Fatalf("Error guardando manifiesto y firma: %v", err)
	}

	// 1. Firma válida
	esValida, err := VerificarFirmaAntesDeDescifrar(rutas, publica)
	if err != nil {
		t.Fatalf("Error verificando firma original: %v", err)
	}
	if !esValida {
		t.Errorf("La firma original debería ser válida")
	}

	// 2. ATAQUE: Alterar solo log.enc (dejando el manifiesto intacto)
	datosManipulados := []byte("esto es un log HACKEADO")
	if err := os.WriteFile(rutas.Cifrado, datosManipulados, 0o600); err != nil {
		t.Fatalf("Error simulando ataque a log.enc: %v", err)
	}

	esValidaDespuesAtaque, err := VerificarFirmaAntesDeDescifrar(rutas, publica)
	if err != nil {
		t.Fatalf("Error verificando firma tras ataque: %v", err)
	}
	if esValidaDespuesAtaque {
		t.Errorf("¡PELIGRO! El sistema no detectó la manipulación de log.enc")
	} else {
		t.Log("✅ ÉXITO: El sistema detectó que log.enc fue alterado y rechazó la firma.")
	}

	// 3. Recuperar estado original para la siguiente prueba
	if err := os.WriteFile(rutas.Cifrado, cifradoOriginal, 0o600); err != nil {
		t.Fatalf("Error restaurando log.enc: %v", err)
	}

	// 4. ATAQUE: Alterar el manifiesto (dejando log.enc intacto)
	bytesManifiestoManipulado, err := CrearManifiesto("log.enc", "hash_falso_inventado", nonceOriginal)
	if err != nil {
		t.Fatalf("Error creando manifiesto manipulado: %v", err)
	}
	if err := os.WriteFile(rutas.Manifiesto, bytesManifiestoManipulado, 0o600); err != nil {
		t.Fatalf("Error simulando ataque al manifiesto: %v", err)
	}

	esValidaManifiesto, err := VerificarFirmaAntesDeDescifrar(rutas, publica)
	if err != nil {
		t.Fatalf("Error verificando firma con manifiesto alterado: %v", err)
	}
	if esValidaManifiesto {
		t.Errorf("¡PELIGRO! El sistema no detectó la manipulación del manifiesto")
	} else {
		t.Log("✅ ÉXITO: El sistema detectó que el manifiesto fue alterado y rechazó la firma.")
	}
}
