package crypto

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Rutas agrupa los archivos que produce la etapa criptográfica.
// Cada artefacto se guarda por separado del log original (Paso 6 y 7).
type Rutas struct {
	Cifrado     string // log cifrado (texto cifrado + etiqueta GCM)
	Clave       string // clave AES-256 (32 bytes)
	Nonce       string // nonce de AES-GCM (12 bytes)
	HashCifrado string // SHA-256 del log cifrado, en hexadecimal
	Manifiesto  string // ruta del manifiesto.json
	Firma       string // ruta del manifiesto.sig
}

// RutasPorDefecto devuelve las rutas con los mismos nombres que usa la CLI
// dentro del directorio indicado (por ejemplo, "salida").
func RutasPorDefecto(dir string) Rutas {
	return Rutas{
		Cifrado:     filepath.Join(dir, "log.enc"),
		Clave:       filepath.Join(dir, "clave.bin"),
		Nonce:       filepath.Join(dir, "nonce.bin"),
		HashCifrado: filepath.Join(dir, "log.enc.sha256"),
		Manifiesto:  filepath.Join(dir, "manifiesto.json"),
		Firma:       filepath.Join(dir, "manifiesto.sig"),
	}
}

// Resultado contiene lo que produce el descifrado y la comparación final (Paso 8 y 9).
type Resultado struct {
	Recuperado     []byte // bytes del log descifrado
	HashDescifrado string // SHA-256 del log descifrado
	HashOriginal   string // SHA-256 del log original en claro (el que se comparó)
	Coinciden      bool   // true si HashDescifrado == HashOriginal
}

// GuardarArtefactos escribe en disco el log cifrado, la clave y el nonce como
// archivos separados, calcula el hash del log cifrado, lo guarda en su propio
// archivo y lo devuelve en hexadecimal.
func GuardarArtefactos(r Rutas, cifrado, clave, nonce []byte) (string, error) {
	if err := escribirArchivo(r.Cifrado, cifrado); err != nil {
		return "", fmt.Errorf("guardando log cifrado: %w", err)
	}
	if err := escribirArchivo(r.Clave, clave); err != nil {
		return "", fmt.Errorf("guardando clave: %w", err)
	}
	if err := escribirArchivo(r.Nonce, nonce); err != nil {
		return "", fmt.Errorf("guardando nonce: %w", err)
	}

	hash := HashSHA256(cifrado)
	if err := escribirArchivo(r.HashCifrado, []byte(hash+"\n")); err != nil {
		return "", fmt.Errorf("guardando hash del log cifrado: %w", err)
	}
	return hash, nil
}

// CargarArtefactos lee desde disco el log cifrado, la clave, el nonce y el
// hash guardado del log cifrado.
func CargarArtefactos(r Rutas) (cifrado, clave, nonce []byte, hashGuardado string, err error) {
	cifrado, err = os.ReadFile(r.Cifrado)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("leyendo log cifrado: %w", err)
	}
	clave, err = os.ReadFile(r.Clave)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("leyendo clave: %w", err)
	}
	nonce, err = os.ReadFile(r.Nonce)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("leyendo nonce: %w", err)
	}
	hashBytes, err := os.ReadFile(r.HashCifrado)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("leyendo hash del log cifrado: %w", err)
	}
	return cifrado, clave, nonce, strings.TrimSpace(string(hashBytes)), nil
}

// VerificarHashCifrado recalcula el SHA-256 del contenido cifrado y lo compara
// con el hash esperado. Devuelve el hash recalculado y si coincide.
func VerificarHashCifrado(cifrado []byte, hashEsperado string) (string, bool) {
	calculado := HashSHA256(cifrado)
	return calculado, calculado == strings.TrimSpace(hashEsperado)
}

// DescifrarYComparar descifra el log, calcula el hash del resultado y lo
// compara con el hash del log original en claro (Paso 8 y 9).
//
// Si el descifrado falla (clave incorrecta o contenido alterado) devuelve un
// error, porque AES-GCM autentica el contenido. Si descifra pero el hash no
// coincide, devuelve el Resultado con Coinciden == false y sin error.
func DescifrarYComparar(cifrado, clave, nonce []byte, hashOriginal string) (Resultado, error) {
	recuperado, err := Descifrar(cifrado, clave, nonce)
	if err != nil {
		return Resultado{}, err
	}

	hashDescifrado := HashSHA256(recuperado)
	hashOriginal = strings.TrimSpace(hashOriginal)

	return Resultado{
		Recuperado:     recuperado,
		HashDescifrado: hashDescifrado,
		HashOriginal:   hashOriginal,
		Coinciden:      hashDescifrado == hashOriginal,
	}, nil
}

// GuardarManifiestoYFirma crea el manifiesto, lo firma con la clave privada
// y guarda ambos archivos en disco.
func GuardarManifiestoYFirma(r Rutas, hashCifrado string, nonce []byte, privada ed25519.PrivateKey) error {
	// 1. Crear el manifiesto
	bytesManifiesto, err := CrearManifiesto("log.enc", hashCifrado, nonce)
	if err != nil {
		return fmt.Errorf("creando manifiesto: %w", err)
	}

	// 2. Firmar el manifiesto
	firma, err := FirmarManifiesto(bytesManifiesto, privada)
	if err != nil {
		return fmt.Errorf("firmando manifiesto: %w", err)
	}

	// 3. Guardar en disco
	if err := escribirArchivo(r.Manifiesto, bytesManifiesto); err != nil {
		return fmt.Errorf("guardando manifiesto: %w", err)
	}
	if err := escribirArchivo(r.Firma, firma); err != nil {
		return fmt.Errorf("guardando firma: %w", err)
	}
	return nil
}

// VerificarFirmaAntesDeDescifrar carga el manifiesto y la firma, y verifica
// que la firma sea válida usando la clave pública.
func VerificarFirmaAntesDeDescifrar(r Rutas, publica ed25519.PublicKey) (bool, error) {
	// 1. Leer manifiesto y firma
	bytesManifiesto, err := os.ReadFile(r.Manifiesto)
	if err != nil {
		return false, fmt.Errorf("leyendo manifiesto: %w", err)
	}
	firma, err := os.ReadFile(r.Firma)
	if err != nil {
		return false, fmt.Errorf("leyendo firma: %w", err)
	}

	// 2. Verificar la firma del manifiesto (autenticidad)
	if !VerificarFirmaManifiesto(bytesManifiesto, firma, publica) {
		return false, nil // Firma inválida
	}

	// 3. AHORA: Verificar que el hash del manifiesto coincida con el archivo real
	// Para eso, decodificamos el manifiesto
	var man Manifiesto
	if err := json.Unmarshal(bytesManifiesto, &man); err != nil {
		return false, fmt.Errorf("error decodificando manifiesto: %w", err)
	}

	// Leemos el archivo cifrado real y calculamos su hash
	cifradoReal, err := os.ReadFile(r.Cifrado)
	if err != nil {
		return false, fmt.Errorf("leyendo archivo cifrado real: %w", err)
	}
	hashReal := HashSHA256(cifradoReal)

	// Comparamos el hash real con el que dice el manifiesto
	if hashReal != man.Hash {
		return false, nil // El archivo fue alterado
	}

	// Todo ok
	return true, nil
}

// escribirArchivo crea el directorio si hace falta y escribe el archivo con
// permisos restringidos (solo el dueño), porque puede contener la clave.
func escribirArchivo(ruta string, contenido []byte) error {
	if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
		return err
	}
	return os.WriteFile(ruta, contenido, 0o600)
}
