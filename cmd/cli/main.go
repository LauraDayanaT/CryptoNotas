package main

import (
	"fmt"
	"os"

	"github.com/LauraDayanaT/cryptonotas/internal/ui"
)

func main() {
	if err := ui.Ejecutar(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
