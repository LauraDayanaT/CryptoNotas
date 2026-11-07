package logbuilder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/LauraDayanaT/cryptonotas/internal/models"
)

// ConstruirLog arma el log completo y valida la cantidad de eventos.
func ConstruirLog(eventos []models.Evento) (models.Log, error) {
	if eventos == nil {
		return models.Log{}, fmt.Errorf("logbuilder: la lista de eventos no puede ser nil")
	}

	log := models.Log{
		Metadatos: models.MetadatosLog{
			VersionEsquema:  "1.0",
			FechaGeneracion: time.Now().UTC().Format(time.RFC3339),
			CantidadEventos: len(eventos),
			SistemaOrigen:   "cryptonotas",
		},
		Eventos: eventos,
	}

	if err := validarLog(log); err != nil {
		return models.Log{}, err
	}
	return log, nil
}

// validarLog verifica la consistencia de los metadatos
// y la integridad individual de cada evento.
func validarLog(log models.Log) error {
	// 1. Validar la cantidad de eventos.
	if log.Metadatos.CantidadEventos != len(log.Eventos) {
		return fmt.Errorf(
			"logbuilder: inconsistencia: metadatos.cantidad_eventos=%d pero len(eventos)=%d",
			log.Metadatos.CantidadEventos, len(log.Eventos),
		)
	}

	// 2. Verificar el hash de cada evento.
	for i, evento := range log.Eventos {
		valido, err := evento.VerificarHashPayload()
		if err != nil {
			return fmt.Errorf(
				"logbuilder: error verificando el evento %d (%s): %w",
				i, evento.IDEvento, err,
			)
		}

		if !valido {
			return fmt.Errorf(
				"logbuilder: integridad comprometida en el evento %d (%s): el hash no coincide con su contenido",
				i, evento.IDEvento,
			)
		}
	}

	return nil
}

// GuardarLog serializa a JSON, guarda en disco y retorna los bytes y el hash.
func GuardarLog(log models.Log, ruta string) ([]byte, string, error) {
	if err := validarLog(log); err != nil {
		return nil, "", err
	}

	bytes, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("logbuilder: error serializando log: %w", err)
	}

	hash := sha256.Sum256(bytes)
	hashHex := hex.EncodeToString(hash[:])

	// Aseguramos que la carpeta exista antes de escribir
	if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
		return nil, "", fmt.Errorf("logbuilder: error creando directorio: %w", err)
	}

	if err := os.WriteFile(ruta, bytes, 0o644); err != nil {
		return nil, "", fmt.Errorf("logbuilder: error escribiendo %s: %w", ruta, err)
	}

	return bytes, hashHex, nil
}

// GuardarHash escribe un hash hexadecimal en un archivo de una sola línea.
func GuardarHash(hashHex, ruta string) error {
	contenido := []byte(hashHex + "\n")

	// Aseguramos que la carpeta exista antes de escribir
	if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
		return fmt.Errorf("logbuilder: error creando directorio: %w", err)
	}

	if err := os.WriteFile(ruta, contenido, 0o644); err != nil {
		return fmt.Errorf("logbuilder: error escribiendo hash en %s: %w", ruta, err)
	}
	return nil
}
