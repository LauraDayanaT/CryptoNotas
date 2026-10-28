package generator

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/LauraDayanaT/cryptonotas/internal/models"
)

func TestGenerarEventos_CantidadYContenido(t *testing.T) {
	const cantidad = 100

	eventos, err := GenerarEventos(cantidad)
	if err != nil {
		t.Fatalf("GenerarEventos devolvió un error: %v", err)
	}

	if len(eventos) != cantidad {
		t.Fatalf("Se esperaban %d eventos, se obtuvieron %d", cantidad, len(eventos))
	}

	registros := 0
	modificaciones := 0

	idsEventos := make(map[string]struct{})
	idsActores := make(map[string]struct{})
	idsEstudiantes := make(map[string]struct{})
	idsCursos := make(map[string]struct{})

	for i, evento := range eventos {
		if evento.IDEvento == "" || evento.ActorUID == "" ||
			evento.EstudianteUID == "" || evento.CursoUID == "" {
			t.Errorf("Evento %d: falta un identificador", i)
		}

		verificarIDUnico(t, idsEventos, evento.IDEvento, "evento", i)
		verificarIDUnico(t, idsActores, evento.ActorUID, "actor", i)
		verificarIDUnico(t, idsEstudiantes, evento.EstudianteUID, "estudiante", i)
		verificarIDUnico(t, idsCursos, evento.CursoUID, "curso", i)

		if evento.NotaNueva < 0 || evento.NotaNueva > 5 {
			t.Errorf("Evento %d: nota nueva fuera de rango: %f", i, evento.NotaNueva)
		}

		if math.Abs(evento.NotaNueva*100-math.Round(evento.NotaNueva*100)) > 1e-9 {
			t.Errorf("Evento %d: la nota nueva debe tener como máximo dos decimales: %f", i, evento.NotaNueva)
		}

		if _, err := time.Parse(time.RFC3339Nano, evento.Timestamp); err != nil {
			t.Errorf("Evento %d: timestamp no válido %q: %v", i, evento.Timestamp, err)
		}

		switch evento.Tipo {
		case models.TipoRegistroNota:
			registros++

			if evento.NotaAnterior != nil {
				t.Errorf("Evento %d: un registro no debe tener nota anterior", i)
			}

		case models.TipoModificacionNota:
			modificaciones++

			if evento.NotaAnterior == nil {
				t.Errorf("Evento %d: una modificación debe tener nota anterior", i)
				break
			}

			if *evento.NotaAnterior < 0 || *evento.NotaAnterior > 5 {
				t.Errorf("Evento %d: nota anterior fuera de rango: %f", i, *evento.NotaAnterior)
			}

			if *evento.NotaAnterior == evento.NotaNueva {
				t.Errorf("Evento %d: una modificación debe cambiar la nota", i)
			}

		default:
			t.Errorf("Evento %d: tipo desconocido: %s", i, evento.Tipo)
		}

		valido, err := evento.VerificarHashPayload()
		if err != nil {
			t.Errorf("Evento %d: error verificando hash: %v", i, err)
		} else if !valido {
			t.Errorf("Evento %d: hash de payload inválido", i)
		}
	}

	if registros == 0 {
		t.Error("La generación no produjo ningún evento REGISTRO_NOTA")
	}

	if modificaciones == 0 {
		t.Error("La generación no produjo ningún evento MODIFICACION_NOTA")
	}

	// Comprueba que los eventos se pueden entregar como JSON y recuperar.
	jsonEventos, err := json.Marshal(eventos)
	if err != nil {
		t.Fatalf("No se pudieron serializar los eventos a JSON: %v", err)
	}

	var recuperados []models.Evento

	if err := json.Unmarshal(jsonEventos, &recuperados); err != nil {
		t.Fatalf("El JSON generado no se pudo leer: %v", err)
	}

	if len(recuperados) != cantidad {
		t.Fatalf(
			"Tras el ciclo JSON se esperaban %d eventos, se obtuvieron %d",
			cantidad,
			len(recuperados),
		)
	}

	for i, evento := range recuperados {
		valido, err := evento.VerificarHashPayload()
		if err != nil || !valido {
			t.Errorf(
				"Evento %d: el hash no se conservó tras serializar JSON (válido=%t, error=%v)",
				i,
				valido,
				err,
			)
		}
	}
}

func verificarIDUnico(
	t *testing.T,
	vistos map[string]struct{},
	id string,
	tipo string,
	indice int,
) {
	t.Helper()

	if _, existe := vistos[id]; existe {
		t.Errorf("Evento %d: ID de %s duplicado: %s", indice, tipo, id)
		return
	}

	vistos[id] = struct{}{}
}

func TestGenerarEventos_CantidadNegativa(t *testing.T) {
	eventos, err := GenerarEventos(-1)

	if err == nil {
		t.Fatal("Se esperaba un error para una cantidad negativa")
	}

	if eventos != nil {
		t.Fatal("Se esperaba nil cuando la cantidad es negativa")
	}
}

func TestGenerarEventos_CantidadCero(t *testing.T) {
	eventos, err := GenerarEventos(0)

	if err != nil {
		t.Fatalf("No se esperaba un error: %v", err)
	}

	if len(eventos) != 0 {
		t.Fatalf("Se esperaban cero eventos, se obtuvieron %d", len(eventos))
	}
}
func TestGenerarEventos_GarantizaAmbosTipos(t *testing.T) {
	eventos, err := GenerarEventos(2)
	if err != nil {
		t.Fatalf("error al generar eventos: %v", err)
	}

	if len(eventos) != 2 {
		t.Fatalf("se esperaban 2 eventos, llegaron %d", len(eventos))
	}

	if eventos[0].Tipo != models.TipoRegistroNota {
		t.Errorf("el primer evento debería ser un registro de nota")
	}

	if eventos[1].Tipo != models.TipoModificacionNota {
		t.Errorf("el segundo evento debería ser una modificación de nota")
	}
}
