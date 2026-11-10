package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Nombres de los archivos de claves dentro del directorio de claves.
const (
	NombreClavePrivada = "privada_ed25519.key"
	NombreClavePublica = "publica_ed25519.pub"
)

// Errores centinela para que el resto del equipo pueda distinguir la causa
// con errors.Is.
var (
	// ErrClavePrivadaInvalida indica una clave privada con tamaño o contenido incorrecto.
	ErrClavePrivadaInvalida = errors.New("clave privada Ed25519 inválida")
	// ErrClavePublicaInvalida indica una clave pública con tamaño incorrecto.
	ErrClavePublicaInvalida = errors.New("clave pública Ed25519 inválida")
	// ErrFirmaInvalida indica que la firma está mal formada o no corresponde
	// al manifiesto y a la clave pública entregados.
	ErrFirmaInvalida = errors.New("firma Ed25519 inválida")
	// ErrManifiestoVacio indica que no hay contenido que firmar o verificar.
	ErrManifiestoVacio = errors.New("manifiesto vacío")
)

// GenerarParClaves crea un par de claves Ed25519 con el generador
// criptográficamente seguro del sistema (crypto/rand).
// La clave privada firma; la pública verifica.
func GenerarParClaves() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publica, privada, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generando par de claves Ed25519: %w", err)
	}
	return publica, privada, nil
}

// validarClavePrivada comprueba el tamaño y que la semilla corresponda a la
// mitad pública embebida (detecta archivos corruptos o manipulados).
func validarClavePrivada(clave ed25519.PrivateKey) error {
	if len(clave) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: tamaño %d bytes, se esperaban %d",
			ErrClavePrivadaInvalida, len(clave), ed25519.PrivateKeySize)
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(clave.Seed()), clave) {
		return fmt.Errorf("%w: la semilla no coincide con la clave pública incluida",
			ErrClavePrivadaInvalida)
	}
	return nil
}

// validarClavePublica comprueba el tamaño de la clave pública.
func validarClavePublica(clave ed25519.PublicKey) error {
	if len(clave) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: tamaño %d bytes, se esperaban %d",
			ErrClavePublicaInvalida, len(clave), ed25519.PublicKeySize)
	}
	return nil
}

// FirmarManifiesto firma los bytes exactos del manifiesto con la clave
// privada y devuelve la firma de 64 bytes. No modifica el manifiesto.
// Falla si el manifiesto está vacío o la clave privada es inválida.
func FirmarManifiesto(manifiesto []byte, clavePrivada ed25519.PrivateKey) ([]byte, error) {
	if len(manifiesto) == 0 {
		return nil, ErrManifiestoVacio
	}
	if err := validarClavePrivada(clavePrivada); err != nil {
		return nil, err
	}
	return ed25519.Sign(clavePrivada, manifiesto), nil
}

// VerificarFirma comprueba que la firma corresponde exactamente a los bytes
// del manifiesto y a la clave pública. Devuelve nil solo si es auténtica;
// en cualquier otro caso devuelve un error y el proceso no debe continuar.
// La clave pública debe provenir de un canal confiable, no del manifiesto.
func VerificarFirma(manifiesto, firma []byte, clavePublica ed25519.PublicKey) error {
	if err := validarClavePublica(clavePublica); err != nil {
		return err
	}
	if len(manifiesto) == 0 {
		return ErrManifiestoVacio
	}
	if len(firma) != ed25519.SignatureSize {
		return fmt.Errorf("%w: tamaño %d bytes, se esperaban %d",
			ErrFirmaInvalida, len(firma), ed25519.SignatureSize)
	}
	if !ed25519.Verify(clavePublica, manifiesto, firma) {
		return fmt.Errorf("%w: no corresponde al manifiesto o a la clave pública", ErrFirmaInvalida)
	}
	return nil
}

// GuardarClaves escribe el par de claves en archivos separados dentro de
// directorio (privada_ed25519.key y publica_ed25519.pub).
//
// Nunca sobrescribe claves existentes, rechaza directorios de artefactos
// (salida/, output/) y restringe el acceso a la clave privada
// (chmod 0600 en Unix, icacls en Windows).
func GuardarClaves(clavePublica ed25519.PublicKey, clavePrivada ed25519.PrivateKey, directorio string) error {
	if err := validarClavePublica(clavePublica); err != nil {
		return err
	}
	if err := validarClavePrivada(clavePrivada); err != nil {
		return err
	}
	if !clavePublica.Equal(clavePrivada.Public()) {
		return errors.New("la clave pública no corresponde a la clave privada")
	}
	if err := rechazarDirectorioDeArtefactos(directorio); err != nil {
		return err
	}

	rutaPrivada := filepath.Join(directorio, NombreClavePrivada)
	rutaPublica := filepath.Join(directorio, NombreClavePublica)

	for _, ruta := range []string{rutaPrivada, rutaPublica} {
		_, err := os.Lstat(ruta)
		if err == nil {
			return fmt.Errorf("ya existe %s: no se sobrescriben claves", ruta)
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("comprobando %s: %w", ruta, err)
		}
	}

	if err := os.MkdirAll(directorio, 0o700); err != nil {
		return fmt.Errorf("creando directorio de claves: %w", err)
	}

	if err := escribirNuevo(rutaPrivada, clavePrivada, 0o600); err != nil {
		return fmt.Errorf("guardando clave privada: %w", err)
	}
	if err := restringirPermisos(rutaPrivada); err != nil {
		_ = os.Remove(rutaPrivada)
		return fmt.Errorf("restringiendo permisos de la clave privada: %w", err)
	}
	if err := escribirNuevo(rutaPublica, clavePublica, 0o644); err != nil {
		_ = os.Remove(rutaPrivada) // no dejar un par incompleto
		return fmt.Errorf("guardando clave pública: %w", err)
	}
	return nil
}

// CargarClavePublica lee una clave pública Ed25519 (32 bytes crudos).
// Detecta archivos inexistentes, vacíos, truncados o de tamaño incorrecto.
func CargarClavePublica(ruta string) (ed25519.PublicKey, error) {
	datos, err := os.ReadFile(ruta)
	if err != nil {
		return nil, fmt.Errorf("leyendo clave pública: %w", err)
	}
	clave := ed25519.PublicKey(datos)
	if err := validarClavePublica(clave); err != nil {
		return nil, err
	}
	return clave, nil
}

// CargarClavePrivada lee una clave privada Ed25519 (64 bytes crudos) y
// comprueba su integridad interna. Detecta archivos inexistentes, vacíos,
// truncados o corruptos.
func CargarClavePrivada(ruta string) (ed25519.PrivateKey, error) {
	datos, err := os.ReadFile(ruta)
	if err != nil {
		return nil, fmt.Errorf("leyendo clave privada: %w", err)
	}
	clave := ed25519.PrivateKey(datos)
	if err := validarClavePrivada(clave); err != nil {
		return nil, err
	}
	return clave, nil
}

// rechazarDirectorioDeArtefactos impide guardar claves dentro de salida/
// u output/, que contienen artefactos que se comparten.
func rechazarDirectorioDeArtefactos(directorio string) error {
	abs, err := filepath.Abs(directorio)
	if err != nil {
		return fmt.Errorf("resolviendo directorio de claves: %w", err)
	}
	for _, parte := range strings.Split(filepath.ToSlash(abs), "/") {
		if strings.EqualFold(parte, "salida") || strings.EqualFold(parte, "output") {
			return fmt.Errorf("las claves no pueden guardarse dentro de %q", parte)
		}
	}
	return nil
}

// escribirNuevo crea el archivo con O_EXCL: falla si ya existe.
func escribirNuevo(ruta string, contenido []byte, permisos os.FileMode) error {
	archivo, err := os.OpenFile(ruta, os.O_WRONLY|os.O_CREATE|os.O_EXCL, permisos)
	if err != nil {
		return err
	}
	if _, err := archivo.Write(contenido); err != nil {
		archivo.Close()
		return err
	}
	if err := archivo.Sync(); err != nil {
		archivo.Close()
		return err
	}
	return archivo.Close()
}
