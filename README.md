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