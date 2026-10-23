package logbuilder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/LauraDayanaT/cryptonotas/internal/models"
)

func eventosDePrueba(n int) []models.Evento {
	eventos := make([]models.Evento, 0, n)
	for i := 0; i < n; i++ {
		payload := models.PayloadEvento{
			IDEvento:      "evt-" + string(rune('a'+i)),
			Tipo:          models.TipoRegistroNota,
			Timestamp:     "2025-01-01T00:00:00Z",
			ActorUID:      "doc-001",
			EstudianteUID: "est-001",
			CursoUID:      "curso-001",
			NotaNueva:     4.2,
		}
		eventos = append(eventos, models.Evento{
			PayloadEvento: payload,
			HashPayload:   "hash-fake",
		})
	}
	return eventos
}

func TestConstruirLog_JSONValido(t *testing.T) {
	log, err := ConstruirLog(eventosDePrueba(3))
	if err != nil {
		t.Fatalf("ConstruirLog devolvió error: %v", err)
	}
	bytes, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("json.Marshal falló: %v", err)
	}
	if !json.Valid(bytes) {
		t.Fatal("el JSON serializado no es válido")
	}
}

func TestConstruirLog_CantidadCorrecta(t *testing.T) {
	log, err := ConstruirLog(eventosDePrueba(5))
	if err != nil {
		t.Fatalf("ConstruirLog devolvió error: %v", err)
	}
	if log.Metadatos.CantidadEventos != 5 {
		t.Fatalf("cantidad_eventos=%d, se esperaba 5", log.Metadatos.CantidadEventos)
	}
	if len(log.Eventos) != 5 {
		t.Fatalf("len(eventos)=%d, se esperaba 5", len(log.Eventos))
	}
}

func TestConstruirLog_NilFalla(t *testing.T) {
	if _, err := ConstruirLog(nil); err == nil {
		t.Fatal("se esperaba error con lista nil")
	}
}

func TestValidarLog_InconsistenciaFalla(t *testing.T) {
	log := models.Log{
		Metadatos: models.MetadatosLog{CantidadEventos: 10},
		Eventos:   eventosDePrueba(2),
	}
	if err := validarLog(log); err == nil {
		t.Fatal("se esperaba error por inconsistencia entre metadatos y len(eventos)")
	}
}

func TestGuardarLog_HashCoincideConArchivoEnDisco(t *testing.T) {
	dir := t.TempDir()
	ruta := filepath.Join(dir, "log_original.json")

	log, err := ConstruirLog(eventosDePrueba(4))
	if err != nil {
		t.Fatalf("ConstruirLog devolvió error: %v", err)
	}

	bytes, hashHex, err := GuardarLog(log, ruta)
	if err != nil {
		t.Fatalf("GuardarLog devolvió error: %v", err)
	}

	recalculado := sha256.Sum256(bytes)
	if hex.EncodeToString(recalculado[:]) != hashHex {
		t.Fatal("el hash devuelto no coincide con el recalculado desde los bytes")
	}

	enDisco, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer el archivo en disco: %v", err)
	}
	hashDisco := sha256.Sum256(enDisco)
	if hex.EncodeToString(hashDisco[:]) != hashHex {
		t.Fatal("el hash recalculado desde el archivo en disco no coincide con el devuelto")
	}

	if string(enDisco) != string(bytes) {
		t.Fatal("los bytes devueltos no coinciden con los del archivo en disco")
	}
}

func TestGuardarHash_EscribeUnaLinea(t *testing.T) {
	dir := t.TempDir()
	ruta := filepath.Join(dir, "log_original.sha256")

	if err := GuardarHash("abcdef123456", ruta); err != nil {
		t.Fatalf("GuardarHash devolvió error: %v", err)
	}

	contenido, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer el hash: %v", err)
	}
	if string(contenido) != "abcdef123456\n" {
		t.Fatalf("contenido inesperado: %q", string(contenido))
	}

}

func TestVerificarHashPayload_DetectaAlteracion(t *testing.T) {
	payload := models.PayloadEvento{
		IDEvento:  "evt-001",
		Tipo:      models.TipoRegistroNota,
		NotaNueva: 4.5,
	}

	// 1. Calculamos el hash original
	hash, err := models.CalcularHashPayload(payload)
	if err != nil {
		t.Fatalf("Error calculando hash: %v", err)
	}

	evento := models.Evento{
		PayloadEvento: payload,
		HashPayload:   hash,
	}

	// 2. Verificamos que el original sea válido
	valido, err := evento.VerificarHashPayload()
	if err != nil || !valido {
		t.Fatal("El hash original debería ser válido")
	}

	// 3. Alteramos la nota (simulamos un hacker)
	evento.NotaNueva = 5.0

	// 4. Verificamos que el sistema detecte la alteración
	valido, err = evento.VerificarHashPayload()
	if err != nil {
		t.Fatalf("Error verificando hash: %v", err)
	}
	if valido {
		t.Fatal("¡Peligro! El sistema no detectó la alteración de la nota")
	}
}
