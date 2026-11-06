package crypto

import (
	"os"
	"testing"
)

func TestManipulacionDeArchivo(t *testing.T) {
	// 1. Preparamos un directorio temporal
	dirTemp := t.TempDir()
	rutas := RutasPorDefecto(dirTemp)

	// 2. Simulamos los datos originales
	cifradoOriginal := []byte("esto es un log cifrado falso, pero firmado")
	nonceOriginal := []byte("nonce1234567")

	// 3. Generamos las claves Ed25519
	publica, privada, err := GenerarClavesEd25519()
	if err != nil {
		t.Fatalf("Error generando claves: %v", err)
	}

	// 4. Guardamos los artefactos originales
	hashCifrado, err := GuardarArtefactos(rutas, cifradoOriginal, []byte("claveFalsa32bytes..."), nonceOriginal)
	if err != nil {
		t.Fatalf("Error guardando artefactos: %v", err)
	}

	// 5. Creamos y firmamos el manifiesto original
	err = GuardarManifiestoYFirma(rutas, hashCifrado, nonceOriginal, privada)
	if err != nil {
		t.Fatalf("Error guardando manifiesto y firma: %v", err)
	}

	// --- PRUEBA 1: Todo está bien (firma válida) ---
	esValida, err := VerificarFirmaAntesDeDescifrar(rutas, publica)
	if err != nil {
		t.Fatalf("Error verificando firma original: %v", err)
	}
	if !esValida {
		t.Errorf("La firma original debería ser válida, pero falló")
	}

	// --- PRUEBA 2: EL ATAQUE (El "Antes" del video) ---
	// El atacante modifica el archivo log.enc
	datosManipulados := []byte("esto es un log HACKEADO, ya no es el original")
	err = os.WriteFile(rutas.Cifrado, datosManipulados, 0o600)
	if err != nil {
		t.Fatalf("Error simulando ataque al cifrado: %v", err)
	}

	// El atacante intenta engañar al sistema: modifica el manifiesto
	// para que el hash coincida con el archivo manipulado.
	// Pero él NO tiene la clave privada, así que la firma no coincidirá.
	bytesManifiestoManipulado, _ := CrearManifiesto("log.enc", "hash_falso_que_el_atacante_inventó", nonceOriginal)
	err = os.WriteFile(rutas.Manifiesto, bytesManifiestoManipulado, 0o600)
	if err != nil {
		t.Fatalf("Error simulando ataque al manifiesto: %v", err)
	}

	// --- PRUEBA 3: Ahora la firma debe fallar (El "Después" del video) ---
	esValidaDespuesDelAtaque, err := VerificarFirmaAntesDeDescifrar(rutas, publica)
	if err != nil {
		t.Fatalf("Error verificando firma manipulada: %v", err)
	}
	if esValidaDespuesDelAtaque {
		t.Errorf("¡PELIGRO! La firma debería ser INVÁLIDA después del ataque, pero pasó")
	} else {
		t.Log("✅ ÉXITO: El sistema detectó la manipulación del manifiesto y rechazó la firma.")
	}
}
