package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const logDePrueba = `{"metadatos":{"cantidad_eventos":1},"eventos":[{"id_evento":"evt-1","nota_nueva":4.25}]}`

func TestGuardarYCargarArtefactos(t *testing.T) {
	original := []byte(logDePrueba)
	cifrado, clave, nonce, err := Cifrar(original)
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}

	rutas := RutasPorDefecto(t.TempDir())
	hash, err := GuardarArtefactos(rutas, cifrado, clave, nonce)
	if err != nil {
		t.Fatalf("GuardarArtefactos devolvió un error: %v", err)
	}
	if hash != HashSHA256(cifrado) {
		t.Fatal("el hash devuelto no corresponde al log cifrado")
	}

	// Los cuatro artefactos deben existir como archivos separados.
	for _, ruta := range []string{rutas.Cifrado, rutas.Clave, rutas.Nonce, rutas.HashCifrado} {
		if _, err := os.Stat(ruta); err != nil {
			t.Fatalf("falta el artefacto %s: %v", ruta, err)
		}
	}

	cifradoDisco, claveDisco, nonceDisco, hashDisco, err := CargarArtefactos(rutas)
	if err != nil {
		t.Fatalf("CargarArtefactos devolvió un error: %v", err)
	}
	if !bytes.Equal(cifradoDisco, cifrado) || !bytes.Equal(claveDisco, clave) || !bytes.Equal(nonceDisco, nonce) {
		t.Fatal("los artefactos leídos de disco no coinciden con los guardados")
	}
	if hashDisco != hash {
		t.Fatalf("hash leído de disco incorrecto: got %s, want %s", hashDisco, hash)
	}
}

func TestGuardarArtefactosCreaDirectorio(t *testing.T) {
	cifrado, clave, nonce, err := Cifrar([]byte(logDePrueba))
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "no", "existe", "aun")
	if _, err := GuardarArtefactos(RutasPorDefecto(dir), cifrado, clave, nonce); err != nil {
		t.Fatalf("debería crear el directorio automáticamente: %v", err)
	}
}

func TestVerificarHashCifrado(t *testing.T) {
	cifrado, _, _, err := Cifrar([]byte(logDePrueba))
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}
	hash := HashSHA256(cifrado)

	if _, ok := VerificarHashCifrado(cifrado, hash); !ok {
		t.Fatal("el hash del archivo intacto debería coincidir")
	}
	if _, ok := VerificarHashCifrado(cifrado, hash+"\n"); !ok {
		t.Fatal("el salto de línea final del archivo de hash no debería afectar la comparación")
	}

	cifrado[len(cifrado)-1] ^= 1
	if _, ok := VerificarHashCifrado(cifrado, hash); ok {
		t.Fatal("el hash debería detectar que el archivo cifrado fue alterado")
	}
}

func TestDescifrarYCompararRecuperaBytesExactos(t *testing.T) {
	original := []byte(logDePrueba)
	hashOriginal := HashSHA256(original)

	cifrado, clave, nonce, err := Cifrar(original)
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}

	res, err := DescifrarYComparar(cifrado, clave, nonce, hashOriginal)
	if err != nil {
		t.Fatalf("DescifrarYComparar devolvió un error: %v", err)
	}
	if !bytes.Equal(res.Recuperado, original) {
		t.Fatal("el descifrado no recuperó los bytes originales")
	}
	if !res.Coinciden {
		t.Fatal("los hashes deberían coincidir")
	}
	if res.HashDescifrado != hashOriginal {
		t.Fatalf("hash descifrado incorrecto: got %s, want %s", res.HashDescifrado, hashOriginal)
	}
}

func TestDescifrarYCompararDetectaHashOriginalDistinto(t *testing.T) {
	cifrado, clave, nonce, err := Cifrar([]byte(logDePrueba))
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}

	hashDeOtroLog := HashSHA256([]byte("otro contenido"))
	res, err := DescifrarYComparar(cifrado, clave, nonce, hashDeOtroLog)
	if err != nil {
		t.Fatalf("DescifrarYComparar devolvió un error: %v", err)
	}
	if res.Coinciden {
		t.Fatal("los hashes no deberían coincidir con un log original distinto")
	}
}

func TestDescifrarYCompararDetectaArchivoAlterado(t *testing.T) {
	original := []byte(logDePrueba)
	cifrado, clave, nonce, err := Cifrar(original)
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}

	cifrado[3] ^= 1
	if _, err := DescifrarYComparar(cifrado, clave, nonce, HashSHA256(original)); err == nil {
		t.Fatal("se esperaba un error al descifrar un archivo alterado")
	}
}

func TestDescifrarConClaveIncorrecta(t *testing.T) {
	original := []byte(logDePrueba)
	cifrado, _, nonce, err := Cifrar(original)
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}

	otraClave := make([]byte, 32)
	if _, err := DescifrarYComparar(cifrado, otraClave, nonce, HashSHA256(original)); err == nil {
		t.Fatal("se esperaba un error al descifrar con una clave incorrecta")
	}
}

func TestCifrarUsaClaveYNonceNuevosCadaVez(t *testing.T) {
	original := []byte(logDePrueba)

	c1, k1, n1, err := Cifrar(original)
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}
	c2, k2, n2, err := Cifrar(original)
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}

	if len(k1) != 32 {
		t.Fatalf("la clave debe ser de 32 bytes (AES-256), got %d", len(k1))
	}
	if len(n1) != 12 {
		t.Fatalf("el nonce de GCM debe ser de 12 bytes, got %d", len(n1))
	}
	if bytes.Equal(k1, k2) || bytes.Equal(n1, n2) || bytes.Equal(c1, c2) {
		t.Fatal("cada cifrado debería usar clave y nonce nuevos")
	}
}

func TestFlujoCompletoDesdeDisco(t *testing.T) {
	original := []byte(logDePrueba)
	hashOriginal := HashSHA256(original)

	cifrado, clave, nonce, err := Cifrar(original)
	if err != nil {
		t.Fatalf("Cifrar devolvió un error: %v", err)
	}

	rutas := RutasPorDefecto(t.TempDir())
	if _, err := GuardarArtefactos(rutas, cifrado, clave, nonce); err != nil {
		t.Fatalf("GuardarArtefactos devolvió un error: %v", err)
	}

	cifradoDisco, claveDisco, nonceDisco, hashGuardado, err := CargarArtefactos(rutas)
	if err != nil {
		t.Fatalf("CargarArtefactos devolvió un error: %v", err)
	}
	if _, ok := VerificarHashCifrado(cifradoDisco, hashGuardado); !ok {
		t.Fatal("el hash del archivo cifrado leído de disco debería coincidir")
	}

	res, err := DescifrarYComparar(cifradoDisco, claveDisco, nonceDisco, hashOriginal)
	if err != nil {
		t.Fatalf("DescifrarYComparar devolvió un error: %v", err)
	}
	if !res.Coinciden || !bytes.Equal(res.Recuperado, original) {
		t.Fatal("el flujo completo debería preservar el log original")
	}
}
