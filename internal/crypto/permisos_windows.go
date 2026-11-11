//go:build windows

package crypto

import (
	"fmt"
	"os/exec"
	"os/user"
	"strings"
)

// restringirPermisos quita la herencia de ACL y concede control total solo al
// usuario actual. En Windows os.WriteFile(..., 0600) no es suficiente: solo
// controla el atributo de solo lectura, no las ACL de NTFS.
func restringirPermisos(ruta string) error {
	actual, err := user.Current()
	if err != nil {
		return fmt.Errorf("obteniendo usuario actual: %w", err)
	}
	salida, err := exec.Command("icacls", ruta, "/inheritance:r", "/grant:r", "*"+actual.Uid+":F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %w (%s)", err, strings.TrimSpace(string(salida)))
	}
	return nil
}
