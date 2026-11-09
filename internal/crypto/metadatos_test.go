package crypto

import (
	"encoding/json"
	"os"
	"testing"
)

func TestMetadatosManifiestoInvalidos(t *testing.T) {
	casos := []struct {
		nombre    string
		modificar func(*Manifiesto)
	}{
		{
			nombre: "version incorrecta",
			modificar: func(m *Manifiesto) {
				m.Version = 99
			},
		},
		{
			nombre: "algoritmo hash incorrecto",
			modificar: func(m *Manifiesto) {
				m.AlgoritmoHash = "MD5"
			},
		},
		{
			nombre: "algoritmo firma incorrecto",
			modificar: func(m *Manifiesto) {
				m.AlgoritmoFirma = "RSA"
			},
		},
		{
			nombre: "nombre de archivo incorrecto",
			modificar: func(m *Manifiesto) {
				m.Archivo = "otro.enc"
			},
		},
	}

	for _, caso := range casos {
		t.Run(caso.nombre, func(t *testing.T) {
			rutas := RutasPorDefecto(t.TempDir())

			publica, privada, err := GenerarClavesEd25519()
			if err != nil {
				t.Fatal(err)
			}

			cifrado := []byte("contenido de prueba")
			nonce := make([]byte, 12)

			hash, err := GuardarArtefactos(
				rutas, cifrado, make([]byte, 32), nonce,
			)
			if err != nil {
				t.Fatal(err)
			}

			manBytes, err := CrearManifiesto("log.enc", hash, nonce)
			if err != nil {
				t.Fatal(err)
			}

			var man Manifiesto
			if err := json.Unmarshal(manBytes, &man); err != nil {
				t.Fatal(err)
			}

			caso.modificar(&man)

			manBytes, err = json.Marshal(man)
			if err != nil {
				t.Fatal(err)
			}

			// Firmamos los metadatos modificados con una clave válida.
			firma, err := FirmarManifiesto(manBytes, privada)
			if err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(rutas.Manifiesto, manBytes, 0600); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(rutas.Firma, firma, 0600); err != nil {
				t.Fatal(err)
			}

			valida, err := VerificarFirmaAntesDeDescifrar(rutas, publica)
			if err != nil {
				t.Fatal(err)
			}

			if valida {
				t.Fatal("se aceptó un manifiesto con metadatos inválidos")
			}
		})
	}
}
