//go:build !windows

package crypto

import "os"

// restringirPermisos deja el archivo accesible solo para su dueño.
func restringirPermisos(ruta string) error {
	return os.Chmod(ruta, 0o600)
}
