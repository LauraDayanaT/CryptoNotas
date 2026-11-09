package crypto

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
)

// CargarOCrearClaves reutiliza las claves Ed25519 existentes.
// Si no existe ninguna, genera un nuevo par.
// Nunca reemplaza automáticamente un par incompleto.
func CargarOCrearClaves(dir string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	rutaPrivada := filepath.Join(dir, "privada_ed25519.key")
	rutaPublica := filepath.Join(dir, "publica_ed25519.pub")

	_, errPriv := os.Stat(rutaPrivada)
	_, errPub := os.Stat(rutaPublica)

	if errPriv == nil && errPub == nil {
		privada, err := os.ReadFile(rutaPrivada)
		if err != nil {
			return nil, nil, fmt.Errorf("leyendo clave privada: %w", err)
		}

		publica, err := os.ReadFile(rutaPublica)
		if err != nil {
			return nil, nil, fmt.Errorf("leyendo clave pública: %w", err)
		}

		if len(privada) != ed25519.PrivateKeySize ||
			len(publica) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("tamaño de claves Ed25519 inválido")
		}

		if !ed25519.PublicKey(publica).Equal(ed25519.PrivateKey(privada).Public()) {
			return nil, nil, fmt.Errorf("la clave pública no corresponde a la privada")
		}

		return ed25519.PublicKey(publica),
			ed25519.PrivateKey(privada), nil
	}

	if (errPriv != nil && !os.IsNotExist(errPriv)) ||
		(errPub != nil && !os.IsNotExist(errPub)) {
		return nil, nil, fmt.Errorf("no se pudo comprobar el estado de las claves")
	}

	if os.IsNotExist(errPriv) != os.IsNotExist(errPub) {
		return nil, nil, fmt.Errorf(
			"par de claves incompleto: no se generarán claves nuevas",
		)
	}

	publica, privada, err := GenerarClavesEd25519()
	if err != nil {
		return nil, nil, err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, fmt.Errorf("creando directorio de claves: %w", err)
	}

	if err := escribirClaveNueva(rutaPrivada, privada); err != nil {
		return nil, nil, fmt.Errorf("guardando clave privada: %w", err)
	}

	if err := escribirClaveNueva(rutaPublica, publica); err != nil {
		return nil, nil, fmt.Errorf("guardando clave pública: %w", err)
	}

	return publica, privada, nil
}

// escribirClaveNueva impide sobrescribir una clave existente.
func escribirClaveNueva(ruta string, contenido []byte) error {
	archivo, err := os.OpenFile(ruta, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer archivo.Close()

	if _, err := archivo.Write(contenido); err != nil {
		return err
	}

	return archivo.Sync()
}
