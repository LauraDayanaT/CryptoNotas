package ui

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	cryptoutil "github.com/LauraDayanaT/cryptonotas/internal/crypto"
	"github.com/LauraDayanaT/cryptonotas/internal/generator"
	"github.com/LauraDayanaT/cryptonotas/internal/logbuilder"
	"github.com/LauraDayanaT/cryptonotas/internal/models"
)

const directorioSalida = "salida"

const (
	rutaOriginal       = directorioSalida + "/log.json"
	rutaHashOriginal   = directorioSalida + "/log.sha256"
	rutaCifrado        = directorioSalida + "/log.enc"
	rutaHashCifrado    = directorioSalida + "/log.enc.sha256"
	rutaClave          = directorioSalida + "/clave.bin"
	rutaNonce          = directorioSalida + "/nonce.bin"
	rutaRecuperado     = directorioSalida + "/log_recuperado.json"
	rutaHashRecuperado = directorioSalida + "/log_recuperado.sha256"
)

// Ejecutar muestra el menú hasta que el usuario seleccione Salir.
func Ejecutar() error {
	for {
		opciones := []string{
			"Generar log de eventos",
			"Descifrar log existente",
			"Salir",
		}

		var seleccion string
		pregunta := &survey.Select{
			Message: "¿Qué deseas hacer?",
			Options: opciones,
		}

		if err := survey.AskOne(pregunta, &seleccion); err != nil {
			return fmt.Errorf("mostrando el menú: %w", err)
		}

		var err error

		switch seleccion {
		case "Generar log de eventos":
			err = generarLog()
		case "Descifrar log existente":
			err = descifrarLogExistente()
		case "Salir":
			fmt.Println("Saliendo de CryptoNotas...")
			return nil
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "\nOperación no completada: %v\n\n", err)
		}
	}
}

// preguntarCantidadEventos vuelve a preguntar hasta recibir un entero positivo.
func preguntarCantidadEventos() (int, error) {
	for {
		var entrada string

		pregunta := &survey.Input{
			Message: "¿Cuántos eventos deseas generar?",
			Help:    "Introduce un número entero mayor que cero.",
		}

		if err := survey.AskOne(pregunta, &entrada); err != nil {
			return 0, fmt.Errorf("leyendo la cantidad: %w", err)
		}

		cantidad, err := strconv.Atoi(strings.TrimSpace(entrada))
		if err != nil || cantidad <= 0 {
			fmt.Println("Entrada inválida: escribe un entero mayor que cero.")
			continue
		}

		return cantidad, nil
	}
}

func generarLog() error {
	cantidad, err := preguntarCantidadEventos()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(directorioSalida, 0700); err != nil {
		return fmt.Errorf("creando directorio de salida: %w", err)
	}

	eventos, err := generator.GenerarEventos(cantidad)
	if err != nil {
		return fmt.Errorf("generando eventos: %w", err)
	}

	log, err := logbuilder.ConstruirLog(eventos)
	if err != nil {
		return fmt.Errorf("construyendo el log: %w", err)
	}

	// GuardarLog devuelve los mismos bytes que escribe y su hash.
	bytesJSON, hashOriginal, err := logbuilder.GuardarLog(log, rutaOriginal)
	if err != nil {
		return fmt.Errorf("guardando el log original: %w", err)
	}

	// Guardar el hash solamente después de guardar correctamente el log.
	if err := logbuilder.GuardarHash(hashOriginal, rutaHashOriginal); err != nil {
		return fmt.Errorf("guardando el hash original: %w", err)
	}

	// Cifrar con una clave aleatoria de 32 bytes y un nonce aleatorio.
	cifrado, clave, nonce, err := cryptoutil.Cifrar(bytesJSON)
	if err != nil {
		return fmt.Errorf("cifrando el log: %w", err)
	}

	// Guardar cada artefacto por separado.
	if err := os.WriteFile(rutaCifrado, cifrado, 0600); err != nil {
		return fmt.Errorf("guardando el log cifrado: %w", err)
	}
	if err := os.WriteFile(rutaClave, clave, 0600); err != nil {
		return fmt.Errorf("guardando la clave: %w", err)
	}
	if err := os.WriteFile(rutaNonce, nonce, 0600); err != nil {
		return fmt.Errorf("guardando el nonce: %w", err)
	}

	hashCifrado := cryptoutil.HashSHA256(cifrado)
	if err := logbuilder.GuardarHash(hashCifrado, rutaHashCifrado); err != nil {
		return fmt.Errorf("guardando el hash cifrado: %w", err)
	}

	// Verificar el hash del archivo cifrado realmente almacenado en disco.
	cifradoDisco, err := os.ReadFile(rutaCifrado)
	if err != nil {
		return fmt.Errorf("leyendo el archivo cifrado: %w", err)
	}

	hashCifradoDisco := cryptoutil.HashSHA256(cifradoDisco)
	if hashCifrado != hashCifradoDisco {
		return fmt.Errorf("integridad incorrecta: el hash del cifrado en disco no coincide")
	}

	// Leer los insumos criptográficos desde disco, no desde memoria.
	claveDisco, err := os.ReadFile(rutaClave)
	if err != nil {
		return fmt.Errorf("leyendo la clave: %w", err)
	}
	nonceDisco, err := os.ReadFile(rutaNonce)
	if err != nil {
		return fmt.Errorf("leyendo el nonce: %w", err)
	}

	recuperado, err := cryptoutil.Descifrar(cifradoDisco, claveDisco, nonceDisco)
	if err != nil {
		return fmt.Errorf("descifrando el log: %w", err)
	}

	if err := os.WriteFile(rutaRecuperado, recuperado, 0600); err != nil {
		return fmt.Errorf("guardando el log recuperado: %w", err)
	}

	hashRecuperado := cryptoutil.HashSHA256(recuperado)
	if err := logbuilder.GuardarHash(hashRecuperado, rutaHashRecuperado); err != nil {
		return fmt.Errorf("guardando el hash recuperado: %w", err)
	}

	coinciden := hashOriginal == hashRecuperado

	mostrarResumen(eventos, hashOriginal, hashCifradoDisco, hashRecuperado, coinciden)

	if !coinciden {
		return fmt.Errorf("integridad incorrecta: el log descifrado no coincide con el original")
	}

	fmt.Println("\nVerificación final correcta: los hashes del original y del descifrado coinciden.")
	return nil
}

// descifrarLogExistente recupera un log usando los artefactos guardados.
func descifrarLogExistente() error {
	cifrado, err := os.ReadFile(rutaCifrado)
	if err != nil {
		return fmt.Errorf("leyendo el log cifrado: %w", err)
	}

	clave, err := os.ReadFile(rutaClave)
	if err != nil {
		return fmt.Errorf("leyendo la clave: %w", err)
	}

	nonce, err := os.ReadFile(rutaNonce)
	if err != nil {
		return fmt.Errorf("leyendo el nonce: %w", err)
	}

	hashOriginalGuardado, err := os.ReadFile(rutaHashOriginal)
	if err != nil {
		return fmt.Errorf("leyendo el hash original: %w", err)
	}

	hashCifradoGuardado, err := os.ReadFile(rutaHashCifrado)
	if err != nil {
		return fmt.Errorf("leyendo el hash cifrado: %w", err)
	}

	hashCifrado := cryptoutil.HashSHA256(cifrado)
	if strings.TrimSpace(string(hashCifradoGuardado)) != hashCifrado {
		return fmt.Errorf("integridad incorrecta: el hash del archivo cifrado no coincide")
	}

	recuperado, err := cryptoutil.Descifrar(cifrado, clave, nonce)
	if err != nil {
		return fmt.Errorf("descifrando el log existente: %w", err)
	}

	if err := os.WriteFile(rutaRecuperado, recuperado, 0600); err != nil {
		return fmt.Errorf("guardando el log recuperado: %w", err)
	}

	hashRecuperado := cryptoutil.HashSHA256(recuperado)
	if err := logbuilder.GuardarHash(hashRecuperado, rutaHashRecuperado); err != nil {
		return fmt.Errorf("guardando el hash recuperado: %w", err)
	}

	coinciden := strings.TrimSpace(string(hashOriginalGuardado)) == hashRecuperado

	fmt.Println("\nResultado del descifrado existente")
	fmt.Println("----------------------------------")
	fmt.Printf("Archivo recuperado: %s\n", rutaRecuperado)
	fmt.Printf("SHA-256 cifrado:    %s\n", hashCifrado)
	fmt.Printf("SHA-256 original:   %s\n", strings.TrimSpace(string(hashOriginalGuardado)))
	fmt.Printf("SHA-256 recuperado: %s\n", hashRecuperado)
	fmt.Printf("¿Coinciden?:        %s\n", resultado(coinciden))

	if !coinciden {
		return fmt.Errorf("el hash recuperado no coincide con %s", rutaHashOriginal)
	}

	fmt.Println("Verificación correcta.")
	return nil
}

func mostrarResumen(
	eventos []models.Evento,
	hashOriginal string,
	hashCifrado string,
	hashRecuperado string,
	coinciden bool,
) {
	registros := 0
	modificaciones := 0

	for _, evento := range eventos {
		switch evento.Tipo {
		case "REGISTRO_NOTA":
			registros++
		case "MODIFICACION_NOTA":
			modificaciones++
		}
	}

	fmt.Println("\n========== RESUMEN FINAL ==========")
	fmt.Printf("Total de eventos:       %d\n", len(eventos))
	fmt.Printf("REGISTRO_NOTA:          %d\n", registros)
	fmt.Printf("MODIFICACION_NOTA:      %d\n", modificaciones)

	fmt.Println("\nEtapa                 SHA-256")
	fmt.Println("-----------------------------------------------")
	fmt.Printf("%-21s %s\n", "Log original", hashOriginal)
	fmt.Printf("%-21s %s\n", "Log cifrado", hashCifrado)
	fmt.Printf("%-21s %s\n", "Log descifrado", hashRecuperado)
	fmt.Println("-----------------------------------------------")
	fmt.Printf("Comparación final: %s\n", resultado(coinciden))
	fmt.Println("===================================")
}

func resultado(coinciden bool) string {
	if coinciden {
		return "COINCIDEN"
	}
	return "NO COINCIDEN"
}
