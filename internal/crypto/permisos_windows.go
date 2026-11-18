//go:build windows

package crypto

import (
	"fmt"
	"os/user"

	"golang.org/x/sys/windows"
)

// restringirPermisos establece una DACL protegida que concede
// control total únicamente al usuario actual de Windows.
func restringirPermisos(ruta string) error {
	actual, err := user.Current()
	if err != nil {
		return fmt.Errorf("obteniendo usuario actual: %w", err)
	}

	// Obtener y validar el SID del usuario actual.
	sid, err := windows.StringToSid(actual.Uid)
	if err != nil {
		return fmt.Errorf("SID del usuario inválido: %w", err)
	}

	// DACL protegida con una única entrada de acceso.
	sddl := fmt.Sprintf("D:P(A;;FA;;;%s)", sid.String())

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("creando descriptor de seguridad: %w", err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("obteniendo DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("DACL inesperadamente nula")
	}

	// Sustituir la DACL existente y deshabilitar su herencia.
	err = windows.SetNamedSecurityInfo(
		ruta,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
	if err != nil {
		return fmt.Errorf("estableciendo permisos de la clave privada: %w", err)
	}

	return nil
}
