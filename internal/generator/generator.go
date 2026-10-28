package generator

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"github.com/LauraDayanaT/cryptonotas/internal/models"
)

// GenerarEventos produce n eventos académicos aleatorios
// y calcula el hash del payload de cada evento.
func GenerarEventos(n int) ([]models.Evento, error) {
	if n < 0 {
		return nil, fmt.Errorf("la cantidad de eventos no puede ser negativa")
	}

	eventos := make([]models.Evento, 0, n)

	for i := 0; i < n; i++ {
		tipo := models.TipoRegistroNota

		if i == 1 {
			// Garantizar que el segundo evento sea una modificación.
			tipo = models.TipoModificacionNota
		} else if i > 1 && rand.Intn(2) == 1 {
			tipo = models.TipoModificacionNota
		}

		notaNueva := generarNota()

		payload := models.PayloadEvento{
			Tipo:      tipo,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			NotaNueva: notaNueva,
		}

		var err error

		payload.IDEvento, err = generarUID("evt")
		if err != nil {
			return nil, fmt.Errorf("generando ID del evento: %w", err)
		}

		payload.ActorUID, err = generarUID("actor")
		if err != nil {
			return nil, fmt.Errorf("generando ID del actor: %w", err)
		}

		payload.EstudianteUID, err = generarUID("est")
		if err != nil {
			return nil, fmt.Errorf("generando ID del estudiante: %w", err)
		}

		payload.CursoUID, err = generarUID("curso")
		if err != nil {
			return nil, fmt.Errorf("generando ID del curso: %w", err)
		}

		if tipo == models.TipoModificacionNota {
			notaAnterior := generarNota()

			// Una modificación debe representar un cambio real de nota.
			// Si ambas notas coinciden, ajustamos una centésima sin salir del rango.
			if notaAnterior == notaNueva {
				if notaAnterior < 5.0 {
					notaAnterior += 0.01
				} else {
					notaAnterior -= 0.01
				}
			}

			payload.NotaAnterior = &notaAnterior
		}

		hash, err := models.CalcularHashPayload(payload)
		if err != nil {
			return nil, fmt.Errorf("calculando hash del evento: %w", err)
		}

		evento := models.Evento{
			PayloadEvento: payload,
			HashPayload:   hash,
		}

		eventos = append(eventos, evento)
	}

	return eventos, nil
}

// generarNota produce una nota aleatoria entre 0.00 y 5.00,
// con valores en incrementos de una centésima.
func generarNota() float64 {
	// Cada nota de 0.00 a 5.00, en pasos de 0.01, tiene la misma probabilidad.
	return float64(rand.Intn(501)) / 100
}

// generarUID crea un identificador aleatorio usando
// el generador criptográficamente seguro de Go.
func generarUID(prefijo string) (string, error) {
	bytes := make([]byte, 8)

	if _, err := cryptorand.Read(bytes); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s-%s", prefijo, hex.EncodeToString(bytes)), nil
}
