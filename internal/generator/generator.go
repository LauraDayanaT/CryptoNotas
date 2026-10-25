package generator

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
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

		if rand.Intn(2) == 1 {
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
	return math.Round(rand.Float64()*500) / 100
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
