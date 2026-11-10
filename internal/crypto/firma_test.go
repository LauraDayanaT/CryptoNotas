package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var manifiestoPrueba = []byte(`{"version":1,"hash":"abc123"}`)

func parDePrueba(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := GenerarParClaves()
	if err != nil {
		t.Fatalf("generando claves: %v", err)
	}
	return pub, priv
}

func TestGenerarParClaves(t *testing.T) {
	pub, priv := parDePrueba(t)

	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("tamaño de clave pública %d", len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("tamaño de clave privada %d", len(priv))
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("la clave pública no corresponde a la privada")
	}

	pub2, _ := parDePrueba(t)
	if bytes.Equal(pub, pub2) {
		t.Fatal("dos generaciones produjeron la misma clave")
	}
}

func TestFirmaValidaSeAcepta(t *testing.T) {
	pub, priv := parDePrueba(t)

	firma, err := FirmarManifiesto(manifiestoPrueba, priv)
	if err != nil {
		t.Fatalf("firmando: %v", err)
	}
	if len(firma) != ed25519.SignatureSize {
		t.Fatalf("tamaño de firma %d", len(firma))
	}
	if err := VerificarFirma(manifiestoPrueba, firma, pub); err != nil {
		t.Fatalf("la firma debería ser válida: %v", err)
	}
}

func TestManifiestoModificadoSeRechaza(t *testing.T) {
	pub, priv := parDePrueba(t)
	firma, err := FirmarManifiesto(manifiestoPrueba, priv)
	if err != nil {
		t.Fatal(err)
	}

	alterado := append([]byte(nil), manifiestoPrueba...)
	alterado[len(alterado)-3] = 'X' // cambia un solo carácter

	err = VerificarFirma(alterado, firma, pub)
	if !errors.Is(err, ErrFirmaInvalida) {
		t.Fatalf("se esperaba ErrFirmaInvalida, se obtuvo %v", err)
	}
}

func TestFirmaModificadaSeRechaza(t *testing.T) {
	pub, priv := parDePrueba(t)
	firma, err := FirmarManifiesto(manifiestoPrueba, priv)
	if err != nil {
		t.Fatal(err)
	}

	firma[0] ^= 0x01 // cambia un bit

	if err := VerificarFirma(manifiestoPrueba, firma, pub); err == nil {
		t.Fatal("se aceptó una firma modificada")
	}
}

func TestClavePublicaIncorrectaSeRechaza(t *testing.T) {
	_, priv := parDePrueba(t)
	otraPub, _ := parDePrueba(t)

	firma, err := FirmarManifiesto(manifiestoPrueba, priv)
	if err != nil {
		t.Fatal(err)
	}

	err = VerificarFirma(manifiestoPrueba, firma, otraPub)
	if !errors.Is(err, ErrFirmaInvalida) {
		t.Fatalf("se esperaba ErrFirmaInvalida, se obtuvo %v", err)
	}
}

func TestFirmaVaciaOMalFormadaSeRechaza(t *testing.T) {
	pub, _ := parDePrueba(t)

	casos := map[string][]byte{
		"nil":   nil,
		"vacía": {},
		"corta": make([]byte, ed25519.SignatureSize-1),
		"larga": make([]byte, ed25519.SignatureSize+1),
		"ceros": make([]byte, ed25519.SignatureSize),
	}
	for nombre, firma := range casos {
		t.Run(nombre, func(t *testing.T) {
			if err := VerificarFirma(manifiestoPrueba, firma, pub); err == nil {
				t.Fatal("se aceptó una firma inválida")
			}
		})
	}
}

func TestFirmarConClavePrivadaInvalida(t *testing.T) {
	_, priv := parDePrueba(t)

	corrupta := append(ed25519.PrivateKey(nil), priv...)
	corrupta[0] ^= 0xFF // la semilla ya no coincide con la mitad pública

	casos := map[string]ed25519.PrivateKey{
		"nil":      nil,
		"vacía":    {},
		"corta":    priv[:ed25519.PrivateKeySize-1],
		"corrupta": corrupta,
	}
	for nombre, clave := range casos {
		t.Run(nombre, func(t *testing.T) {
			firma, err := FirmarManifiesto(manifiestoPrueba, clave)
			if !errors.Is(err, ErrClavePrivadaInvalida) {
				t.Fatalf("se esperaba ErrClavePrivadaInvalida, se obtuvo %v", err)
			}
			if firma != nil {
				t.Fatal("no debe devolver firma con clave inválida")
			}
		})
	}
}

func TestVerificarConClavePublicaInvalida(t *testing.T) {
	_, priv := parDePrueba(t)
	firma, err := FirmarManifiesto(manifiestoPrueba, priv)
	if err != nil {
		t.Fatal(err)
	}

	casos := map[string]ed25519.PublicKey{
		"nil":   nil,
		"corta": make(ed25519.PublicKey, ed25519.PublicKeySize-1),
		"larga": make(ed25519.PublicKey, ed25519.PublicKeySize+1),
	}
	for nombre, clave := range casos {
		t.Run(nombre, func(t *testing.T) {
			err := VerificarFirma(manifiestoPrueba, firma, clave)
			if !errors.Is(err, ErrClavePublicaInvalida) {
				t.Fatalf("se esperaba ErrClavePublicaInvalida, se obtuvo %v", err)
			}
		})
	}
}

func TestManifiestoVacioSeRechaza(t *testing.T) {
	pub, priv := parDePrueba(t)

	if _, err := FirmarManifiesto(nil, priv); !errors.Is(err, ErrManifiestoVacio) {
		t.Fatalf("firmar vacío: %v", err)
	}
	if err := VerificarFirma([]byte{}, make([]byte, ed25519.SignatureSize), pub); !errors.Is(err, ErrManifiestoVacio) {
		t.Fatalf("verificar vacío: %v", err)
	}
}

func TestFirmarNoModificaElManifiesto(t *testing.T) {
	_, priv := parDePrueba(t)
	copia := append([]byte(nil), manifiestoPrueba...)

	if _, err := FirmarManifiesto(copia, priv); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copia, manifiestoPrueba) {
		t.Fatal("FirmarManifiesto modificó el contenido original")
	}
}

func TestGuardarYCargarClaves(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claves")
	pub, priv := parDePrueba(t)

	if err := GuardarClaves(pub, priv, dir); err != nil {
		t.Fatalf("guardando claves: %v", err)
	}

	rutaPriv := filepath.Join(dir, NombreClavePrivada)
	rutaPub := filepath.Join(dir, NombreClavePublica)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(rutaPriv)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("permisos de la clave privada: %v", info.Mode().Perm())
		}
	}

	privCargada, err := CargarClavePrivada(rutaPriv)
	if err != nil {
		t.Fatalf("cargando privada: %v", err)
	}
	pubCargada, err := CargarClavePublica(rutaPub)
	if err != nil {
		t.Fatalf("cargando pública: %v", err)
	}
	if !bytes.Equal(priv, privCargada) || !bytes.Equal(pub, pubCargada) {
		t.Fatal("las claves cargadas no coinciden con las guardadas")
	}

	// Firmar con la privada cargada y verificar con la pública cargada.
	firma, err := FirmarManifiesto(manifiestoPrueba, privCargada)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerificarFirma(manifiestoPrueba, firma, pubCargada); err != nil {
		t.Fatalf("la firma con claves cargadas debería ser válida: %v", err)
	}
}

func TestGuardarClavesNoSobrescribe(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claves")
	pub, priv := parDePrueba(t)

	if err := GuardarClaves(pub, priv, dir); err != nil {
		t.Fatal(err)
	}

	pub2, priv2 := parDePrueba(t)
	if err := GuardarClaves(pub2, priv2, dir); err == nil {
		t.Fatal("se sobrescribió un par de claves existente")
	}

	// La clave original sigue intacta.
	cargada, err := CargarClavePrivada(filepath.Join(dir, NombreClavePrivada))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cargada, priv) {
		t.Fatal("la clave privada original fue alterada")
	}
}

func TestGuardarClavesRechazaDirectorioSalida(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "salida")
	pub, priv := parDePrueba(t)

	if err := GuardarClaves(pub, priv, dir); err == nil {
		t.Fatal("se guardaron claves dentro de salida/")
	}
	if _, err := os.Stat(filepath.Join(dir, NombreClavePrivada)); !os.IsNotExist(err) {
		t.Fatal("no debía crearse la clave privada en salida/")
	}
}

func TestGuardarClavesRechazaParQueNoCorresponde(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claves")
	pub, _ := parDePrueba(t)
	_, otraPriv := parDePrueba(t)

	if err := GuardarClaves(pub, otraPriv, dir); err == nil {
		t.Fatal("se aceptó un par que no corresponde")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("no debía crearse el directorio de claves")
	}
}

func TestCargarClavesInvalidasOIncompletas(t *testing.T) {
	dir := t.TempDir()
	pub, priv := parDePrueba(t)

	escribir := func(nombre string, datos []byte) string {
		ruta := filepath.Join(dir, nombre)
		if err := os.WriteFile(ruta, datos, 0o600); err != nil {
			t.Fatal(err)
		}
		return ruta
	}

	// Archivo inexistente.
	if _, err := CargarClavePrivada(filepath.Join(dir, "no_existe.key")); err == nil {
		t.Fatal("se esperaba error con archivo inexistente (privada)")
	}
	if _, err := CargarClavePublica(filepath.Join(dir, "no_existe.pub")); err == nil {
		t.Fatal("se esperaba error con archivo inexistente (pública)")
	}

	// Archivos vacíos y truncados.
	if _, err := CargarClavePrivada(escribir("vacia.key", nil)); !errors.Is(err, ErrClavePrivadaInvalida) {
		t.Fatalf("privada vacía: %v", err)
	}
	if _, err := CargarClavePrivada(escribir("trunca.key", priv[:40])); !errors.Is(err, ErrClavePrivadaInvalida) {
		t.Fatalf("privada truncada: %v", err)
	}
	if _, err := CargarClavePublica(escribir("vacia.pub", nil)); !errors.Is(err, ErrClavePublicaInvalida) {
		t.Fatalf("pública vacía: %v", err)
	}
	if _, err := CargarClavePublica(escribir("trunca.pub", pub[:10])); !errors.Is(err, ErrClavePublicaInvalida) {
		t.Fatalf("pública truncada: %v", err)
	}

	// Clave privada con contenido corrupto pero del tamaño correcto.
	corrupta := append([]byte(nil), priv...)
	corrupta[5] ^= 0xFF
	if _, err := CargarClavePrivada(escribir("corrupta.key", corrupta)); !errors.Is(err, ErrClavePrivadaInvalida) {
		t.Fatalf("privada corrupta: %v", err)
	}
}

// Verifica el flujo acordado con Laura: se firman y verifican los bytes
// exactos del manifiesto, sin volver a serializar el JSON.
func TestFlujoManifiestoReal(t *testing.T) {
	dir := t.TempDir()
	dirClaves := filepath.Join(dir, "claves")
	pub, priv := parDePrueba(t)
	if err := GuardarClaves(pub, priv, dirClaves); err != nil {
		t.Fatal(err)
	}

	manifiesto, err := CrearManifiesto("log.enc", HashSHA256([]byte("cifrado")), make([]byte, 12))
	if err != nil {
		t.Fatal(err)
	}

	clavePrivada, err := CargarClavePrivada(filepath.Join(dirClaves, NombreClavePrivada))
	if err != nil {
		t.Fatal(err)
	}
	firma, err := FirmarManifiesto(manifiesto, clavePrivada)
	if err != nil {
		t.Fatal(err)
	}

	rutaManifiesto := filepath.Join(dir, "manifiesto.json")
	rutaFirma := filepath.Join(dir, "manifiesto.sig")
	if err := os.WriteFile(rutaManifiesto, manifiesto, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rutaFirma, firma, 0o600); err != nil {
		t.Fatal(err)
	}

	clavePublica, err := CargarClavePublica(filepath.Join(dirClaves, NombreClavePublica))
	if err != nil {
		t.Fatal(err)
	}
	manifiestoLeido, err := os.ReadFile(rutaManifiesto)
	if err != nil {
		t.Fatal(err)
	}
	firmaLeida, err := os.ReadFile(rutaFirma)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerificarFirma(manifiestoLeido, firmaLeida, clavePublica); err != nil {
		t.Fatalf("la firma sobre los bytes originales debería ser válida: %v", err)
	}

	// El mismo JSON re-serializado (compactado) cambia los bytes y la firma deja de valer.
	var compacto bytes.Buffer
	if err := json.Compact(&compacto, manifiestoLeido); err != nil {
		t.Fatal(err)
	}
	if err := VerificarFirma(compacto.Bytes(), firmaLeida, clavePublica); err == nil {
		t.Fatal("se aceptó un manifiesto re-serializado con bytes distintos")
	}
}
