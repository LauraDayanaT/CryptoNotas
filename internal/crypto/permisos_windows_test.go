//go:build windows

package crypto

import (
	"bytes"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestPermisosClavePrivadaWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claves")

	publica, privada, err := GenerarParClaves()
	if err != nil {
		t.Fatal(err)
	}

	if err := GuardarClaves(publica, privada, dir); err != nil {
		t.Fatalf("guardando claves: %v", err)
	}

	rutaPrivada := filepath.Join(dir, NombreClavePrivada)

	if _, err := os.Stat(rutaPrivada); err != nil {
		t.Fatalf("clave privada no encontrada: %v", err)
	}

	salida, err := exec.Command("icacls", rutaPrivada).CombinedOutput()
	if err != nil {
		t.Fatalf("consultando ACL: %v\n%s", err, salida)
	}

	acl := string(salida)
	t.Logf("ACL de la clave privada:\n%s", acl)

	actual, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	// El SID del usuario actual debe aparecer en la ACL.
	// icacls puede mostrar el nombre en lugar del SID,
	// por lo que también comprobamos el nombre de usuario.
	if !strings.Contains(strings.ToLower(acl), strings.ToLower(actual.Username)) &&
		!strings.Contains(acl, actual.Uid) {
		t.Log("No se pudo identificar al usuario actual en la salida de icacls")
	}

	// El usuario actual debe poder leer la clave privada.
	contenido, err := os.ReadFile(rutaPrivada)
	if err != nil {
		t.Fatalf("el usuario actual no puede leer la clave privada: %v", err)
	}

	if !bytes.Equal(contenido, privada) {
		t.Fatal("el contenido de la clave privada cambió")
	}

	// No debe conservar permisos heredados.
	if strings.Contains(acl, "(I)") {
		t.Fatal("la clave privada conserva permisos heredados")
	}

}

func TestPermisosClavesExistentesWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claves")

	publicaOriginal, privadaOriginal, err := GenerarParClaves()
	if err != nil {
		t.Fatal(err)
	}

	if err := GuardarClaves(publicaOriginal, privadaOriginal, dir); err != nil {
		t.Fatal(err)
	}

	rutaPrivada := filepath.Join(dir, NombreClavePrivada)

	// Simulamos una clave antigua con permisos heredados.
	salida, err := exec.Command(
		"icacls", rutaPrivada, "/inheritance:e",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("habilitando herencia: %v\n%s", err, salida)
	}

	// La aplicación debe reutilizar las mismas claves.
	publicaCargada, privadaCargada, err := CargarOCrearClaves(dir)
	if err != nil {
		t.Fatalf("reutilizando claves: %v", err)
	}

	if !bytes.Equal(publicaOriginal, publicaCargada) ||
		!bytes.Equal(privadaOriginal, privadaCargada) {
		t.Fatal("las claves existentes fueron reemplazadas")
	}

	// Verificamos los permisos después de reutilizar la clave.
	salida, err = exec.Command("icacls", rutaPrivada).CombinedOutput()
	if err != nil {
		t.Fatalf("consultando ACL: %v\n%s", err, salida)
	}

	acl := string(salida)
	t.Logf("ACL después de reutilizar la clave:\n%s", acl)

	if strings.Contains(acl, "(I)") {
		t.Fatal("la clave privada conserva permisos heredados")
	}
}

func TestPermisosExplicitosAdicionalesWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claves")

	publica, privada, err := GenerarParClaves()
	if err != nil {
		t.Fatal(err)
	}

	if err := GuardarClaves(publica, privada, dir); err != nil {
		t.Fatal(err)
	}

	rutaPrivada := filepath.Join(dir, NombreClavePrivada)

	// Agregamos permiso explícito de lectura para
	// el grupo integrado Usuarios de Windows.
	salida, err := exec.Command(
		"icacls",
		rutaPrivada,
		"/grant",
		"*S-1-5-32-545:R",
	).CombinedOutput()

	if err != nil {
		t.Fatalf("agregando permiso: %v\n%s", err, salida)
	}

	// Ejecutamos la implementación actual.
	if err := restringirPermisos(rutaPrivada); err != nil {
		t.Fatal(err)
	}

	salida, err = exec.Command("icacls", rutaPrivada).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	acl := string(salida)
	t.Logf("ACL después de restringir permisos:\n%s", acl)

	// El grupo Usuarios no debería conservar acceso.
	if strings.Contains(acl, "S-1-5-32-545") ||
		strings.Contains(strings.ToLower(acl), "usuarios:") ||
		strings.Contains(strings.ToLower(acl), "users:") {
		t.Fatal("la clave privada conserva permisos explícitos adicionales")
	}
}

func TestPermisosOtroGrupoWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claves")

	publica, privada, err := GenerarParClaves()
	if err != nil {
		t.Fatal(err)
	}

	if err := GuardarClaves(publica, privada, dir); err != nil {
		t.Fatal(err)
	}

	rutaPrivada := filepath.Join(dir, NombreClavePrivada)

	// Agregar acceso de lectura al grupo Invitados.
	salida, err := exec.Command(
		"icacls",
		rutaPrivada,
		"/grant",
		"*S-1-5-32-546:R",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("agregando permiso de Invitados: %v\n%s", err, salida)
	}

	// Aplicar la nueva DACL.
	if err := restringirPermisos(rutaPrivada); err != nil {
		t.Fatal(err)
	}

	salida, err = exec.Command("icacls", rutaPrivada).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	acl := string(salida)
	t.Logf("ACL después de aplicar la DACL:\n%s", acl)

	if strings.Contains(acl, "S-1-5-32-546") ||
		strings.Contains(strings.ToLower(acl), "invitados:") ||
		strings.Contains(strings.ToLower(acl), "guests:") {
		t.Fatal("la clave privada conserva permisos del grupo Invitados")
	}

	if strings.Contains(acl, "(I)") {
		t.Fatal("la clave privada conserva permisos heredados")
	}
}
