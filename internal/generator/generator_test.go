package generator

import (
	"testing"

	"github.com/LauraDayanaT/cryptonotas/internal/models"
)

func TestGenerarEventos_CantidadYContenido(t *testing.T) {
	const cantidad = 100

	eventos, err := GenerarEventos(cantidad)
	if err != nil {
		t.Fatalf("GenerarEventos devolvió un error: %v", err)
	}

	if len(eventos) != cantidad {
		t.Fatalf("Se esperaban %d eventos, se obtuvieron %d",
			cantidad, len(eventos))
	}

	for i, evento := range eventos {
		if evento.IDEvento == "" ||
			evento.ActorUID == "" ||
			evento.EstudianteUID == "" ||
			evento.CursoUID == "" {
			t.Errorf("Evento %d: falta un identificador", i)
		}

		if evento.NotaNueva < 0 || evento.NotaNueva > 5 {
			t.Errorf("Evento %d: nota fuera de rango: %f",
				i, evento.NotaNueva)
		}

		switch evento.Tipo {
		case models.TipoRegistroNota:
			if evento.NotaAnterior != nil {
				t.Errorf("Evento %d: un registro no debe tener nota anterior", i)
			}

		case models.TipoModificacionNota:
			if evento.NotaAnterior == nil {
				t.Errorf("Evento %d: una modificación debe tener nota anterior", i)
			} else if *evento.NotaAnterior < 0 || *evento.NotaAnterior > 5 {
				t.Errorf("Evento %d: nota anterior fuera de rango", i)
			}

		default:
			t.Errorf("Evento %d: tipo desconocido: %s", i, evento.Tipo)
		}

		if evento.Timestamp == "" {
			t.Errorf("Evento %d: falta la marca de tiempo", i)
		}

		valido, err := evento.VerificarHashPayload()
		if err != nil {
			t.Errorf("Evento %d: error verificando hash: %v", i, err)
		} else if !valido {
			t.Errorf("Evento %d: hash de payload inválido", i)
		}
	}
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
		t.Fatalf("Se esperaban cero eventos, se obtuvieron %d",
			len(eventos))
	}
}
