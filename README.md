# Taller Dos – Criptografía: Protección de logs estructurados en reposo

Herramienta CLI en Go que genera logs estructurados de eventos académicos
(registro y modificación de notas) y los protege mediante hashing (SHA-256)
y cifrado, verificando integridad, confidencialidad y verificabilidad
durante el ciclo de almacenamiento y recuperación.

## Integrantes

| Nombre | Módulo principal |
|--------|------------------|
| Daniel Escobar Escobar | Generación de eventos y hash del payload |
| Laura Dayana Tascon | Construcción del log y hash en claro |
| Enrique Lozano Abella | Cifrado, descifrado y verificación |
| Leandro Moreno Castillo | Interfaz CLI e integración |

- Curso: Ciberseguridad
- Profesor: Ivan Cabezas Troyano
- Universidad: Universidad del Valle
- Fecha: 22 de octubre de 2026

## Flujo de la aplicación

1. Solicitud de la cantidad de eventos a generar
2. Generación aleatoria de eventos (registro y modificación de nota)
3. Hash del payload de cada evento
4. Construcción del log completo en JSON
5. Hash del log en claro
6. Cifrado del log
7. Hash del log cifrado
8. Descifrado del log
9. Hash del log descifrado y comparación con el original
10. Presentación de resultados

## Requisitos

- Go 1.22 o superior
- Librería de terceros para el menú CLI: (a definir por Leandro)

## Instalación y ejecución

```bash
git clone https://github.com/LauraDayanaT/CryptoNotas.git
cd CryptoNotas
go mod tidy
go run ./cmd/cli
```

## Estructura del proyecto

| Carpeta | Descripción |
|---------|-------------|
| `cmd/cli` | Punto de entrada de la aplicación |
| `internal/models` | Estructuras de datos del evento y del log |
| `internal/generator` | Generación aleatoria de eventos y hash del payload |
| `internal/logbuilder` | Construcción, almacenamiento y hash del log |
| `internal/crypto` | Cifrado, descifrado y funciones de hash |
| `internal/ui` | Menús interactivos |
| `docs/diagramas` | Diagramas de estructura y de comportamiento |
| `output` | Archivos generados (no se versionan) |

## Decisiones de diseño

- **Hash:** SHA-256 (`crypto/sha256`)
- **Cifrado:** AES-256-GCM (`crypto/aes` + `crypto/cipher`)
- **Origen de la clave y el nonce:** `crypto/rand`
- **Hash del payload:** se calcula serializando un struct (`PayloadEvento`) que
  **no incluye** el campo `hash_payload`, lo que evita la dependencia circular
  y garantiza un orden de campos determinista. La función oficial es
  `models.CalcularHashPayload`.

## Archivos generados

| Archivo | Contenido |
|---------|-----------|
| `log_original.json` | Log en texto plano |
| `log_original.sha256` | Hash del log en claro |
| `log_cifrado.bin` | Log cifrado |
| `log_cifrado.sha256` | Hash del log cifrado |
| `clave.key` / `nonce.bin` | Insumos criptográficos |
| `log_descifrado.json` | Log recuperado |
| `log_descifrado.sha256` | Hash del log descifrado |

## Pruebas

```bash
go test ./...
```

## Declaración de uso responsable de IA

[Completar entre todos: qué herramientas de IA se usaron (por ejemplo,
asistentes de IA para repartir el trabajo y revisar el código), para qué
tareas concretas, y cómo se verificó y comprendió el resultado antes de
incluirlo en el proyecto.]

## Licencia / Uso académico

Proyecto desarrollado con fines académicos.