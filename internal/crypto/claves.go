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
	rutaPrivada := filepath.Join(dir, NombreClavePrivada)
	rutaPublica := filepath.Join(dir, NombreClavePublica)

	_, errPriv := os.Stat(rutaPrivada)
	_, errPub := os.Stat(rutaPublica)

	if errPriv == nil && errPub == nil {
		privada, err := CargarClavePrivada(rutaPrivada)
		if err != nil {
			return nil, nil, err
		}

		publica, err := CargarClavePublica(rutaPublica)
		if err != nil {
			return nil, nil, err
		}

		if !publica.Equal(privada.Public()) {
			return nil, nil, fmt.Errorf("la clave pública no corresponde a la privada")
		}

		return publica, privada, nil
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

	publica, privada, err := GenerarParClaves()
	if err != nil {
		return nil, nil, err
	}

	if err := GuardarClaves(publica, privada, dir); err != nil {
		return nil, nil, err
	}

	return publica, privada, nil
}
