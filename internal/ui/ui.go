package ui

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/LauraDayanaT/cryptonotas/internal/crypto"
	"github.com/LauraDayanaT/cryptonotas/internal/generator"
	"github.com/LauraDayanaT/cryptonotas/internal/logbuilder"
)

// Ejecutar muestra el menú principal del programa.
func Ejecutar() error {
	opciones := []string{
		"Generar log de eventos",
		"Salir",
	}
	var seleccion string
	pregunta := &survey.Select{
		Message: "¿Qué deseas hacer?",
		Options: opciones,
	}
	err := survey.AskOne(pregunta, &seleccion)
	if err != nil {
		return fmt.Errorf("error mostrando el menú: %w", err)
	}
	switch seleccion {
	case "Generar log de eventos":
		return preguntarCantidadEventos()
	case "Salir":
		fmt.Println("Saliendo de CryptoNotas...")
	}
	return nil
}
func preguntarCantidadEventos() error {
	var cantidad int
	pregunta := &survey.Input{
		Message: "¿Cuántos eventos deseas generar?",
	}
	err := survey.AskOne(
		pregunta,
		&cantidad,
		survey.WithValidator(survey.Required),
	)
	if err != nil {
		return fmt.Errorf("error leyendo la cantidad: %w", err)
	}
	if cantidad < 1 {
		return fmt.Errorf("la cantidad debe ser mayor que cero")
	}

	eventos, err := generator.GenerarEventos(cantidad)
	if err != nil {
		return fmt.Errorf("error generando eventos: %w", err)
	}

	log, err := logbuilder.ConstruirLog(eventos)
	if err != nil {
		return fmt.Errorf("error construyendo el log: %w", err)
	}

	ruta := "salida/log.json"

	bytesJSON, hashOriginal, err := logbuilder.GuardarLog(log, ruta)
	if err != nil {
		if err := logbuilder.GuardarHash(hashOriginal, "salida/log.sha256"); err != nil {
			return fmt.Errorf("error guardando el hash original: %w", err)
		}
		return fmt.Errorf("error guardando el log: %w", err)
	}

	// Cifrar el JSON en memoria.
	cifrado, clave, nonce, err := crypto.Cifrar(bytesJSON)
	if err != nil {
		return fmt.Errorf("error cifrando el log: %w", err)
	}

	// Guardar el contenido cifrado.
	rutaCifrado := "salida/log.enc"
	if err := os.WriteFile(rutaCifrado, cifrado, 0600); err != nil {
		return fmt.Errorf("error guardando el log cifrado: %w", err)
	}

	// Guardar temporalmente la clave y el nonce por separado.
	// En el siguiente paso mejoraremos la protección de la clave.
	if err := os.WriteFile("salida/clave.bin", clave, 0600); err != nil {
		return fmt.Errorf("error guardando la clave: %w", err)
	}
	if err := os.WriteFile("salida/nonce.bin", nonce, 0600); err != nil {
		return fmt.Errorf("error guardando el nonce: %w", err)
	}

	fmt.Printf("Se generaron %d eventos correctamente.\n", len(eventos))
	fmt.Printf("Log original: %s\n", ruta)
	fmt.Printf("SHA-256 original: %s\n", hashOriginal)
	hashCifrado := crypto.HashSHA256(cifrado)

	fmt.Printf("Log cifrado: %s\n", rutaCifrado)
	fmt.Printf("SHA-256 cifrado: %s\n", hashCifrado)

	if err := logbuilder.GuardarHash(hashCifrado, "salida/log.enc.sha256"); err != nil {
		return fmt.Errorf("error guardando el hash del log cifrado: %w", err)
	}

	// Leer el archivo cifrado desde el disco y verificar su hash.
	cifradoDisco, err := os.ReadFile(rutaCifrado)
	if err != nil {
		return fmt.Errorf("error leyendo el log cifrado: %w", err)
	}

	hashCifradoDisco := crypto.HashSHA256(cifradoDisco)

	if hashCifrado != hashCifradoDisco {
		return fmt.Errorf("integridad incorrecta: el archivo cifrado cambió")
	}

	fmt.Println("Verificación correcta: el hash del archivo cifrado coincide.")

	// Descifrar el contenido cifrado.
	recuperado, err := crypto.Descifrar(cifrado, clave, nonce)
	if err != nil {
		return fmt.Errorf("error descifrando el log: %w", err)
	}

	// Comparar el hash del contenido recuperado con el original.
	hashRecuperado := crypto.HashSHA256(recuperado)

	fmt.Printf("SHA-256 recuperado: %s\n", hashRecuperado)

	rutaRecuperado := "salida/log_recuperado.json"

	if err := os.WriteFile(rutaRecuperado, recuperado, 0600); err != nil {
		return fmt.Errorf("error guardando el log recuperado: %w", err)
	}

	fmt.Printf("Log recuperado guardado en: %s\n", rutaRecuperado)

	if hashOriginal != hashRecuperado {
		return fmt.Errorf("integridad incorrecta: el contenido recuperado no coincide con el original")
	}
	fmt.Println("Verificación correcta: el JSON recuperado coincide con el original.")
	return nil
}
