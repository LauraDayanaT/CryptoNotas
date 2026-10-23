package models

import "testing"

func TestVerificarHashPayload_DetectaAlteracion(t *testing.T) {
	notaAnterior := 3.5
	payload := PayloadEvento{
		IDEvento:     "evt-001",
		Tipo:         TipoModificacionNota,
		NotaAnterior: &notaAnterior,
		NotaNueva:    4.5,
	}

	hash, err := CalcularHashPayload(payload)
	if err != nil {
		t.Fatalf("Error calculando hash: %v", err)
	}

	evento := Evento{
		PayloadEvento: payload,
		HashPayload:   hash,
	}

	valido, err := evento.VerificarHashPayload()
	if err != nil || !valido {
		t.Fatal("El hash original debería ser válido")
	}

	// Simulamos un hacker alterando la nota nueva
	evento.NotaNueva = 5.0

	valido, err = evento.VerificarHashPayload()
	if err != nil {
		t.Fatalf("Error verificando hash: %v", err)
	}
	if valido {
		t.Fatal("¡Peligro! El sistema no detectó la alteración de la nota")
	}

	// Simulamos alterar la nota ANTERIOR
	evento.NotaNueva = 4.5 // Restauramos la nueva
	nuevaAnterior := 1.0
	evento.NotaAnterior = &nuevaAnterior

	valido, err = evento.VerificarHashPayload()
	if err != nil {
		t.Fatalf("Error verificando hash: %v", err)
	}
	if valido {
		t.Fatal("¡Peligro! El sistema no detectó la alteración de la nota anterior")
	}
}
