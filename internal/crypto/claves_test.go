package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistenciaClavesEd25519(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claves")

	// Primera ejecución: generar claves.
	publica1, privada1, err := CargarOCrearClaves(dir)
	if err != nil {
		t.Fatalf("error generando claves: %v", err)
	}

	// Segunda ejecución: reutilizar las mismas claves.
	publica2, privada2, err := CargarOCrearClaves(dir)
	if err != nil {
		t.Fatalf("error cargando claves: %v", err)
	}

	if !bytes.Equal(publica1, publica2) {
		t.Fatal("la clave pública cambió entre ejecuciones")
	}

	if !bytes.Equal(privada1, privada2) {
		t.Fatal("la clave privada cambió entre ejecuciones")
	}
}

func TestClavesIncompletas(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claves")

	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}

	// Crear solamente una clave pública.
	rutaPublica := filepath.Join(dir, "publica_ed25519.pub")
	if err := os.WriteFile(rutaPublica, []byte("clave incompleta"), 0600); err != nil {
		t.Fatal(err)
	}

	// No debe generar ni reemplazar claves automáticamente.
	_, _, err := CargarOCrearClaves(dir)
	if err == nil {
		t.Fatal("se esperaba un error por claves incompletas")
	}

	// Comprobar que no creó una clave privada.
	rutaPrivada := filepath.Join(dir, "privada_ed25519.key")
	if _, err := os.Stat(rutaPrivada); !os.IsNotExist(err) {
		t.Fatal("no debía crearse una clave privada")
	}
}
