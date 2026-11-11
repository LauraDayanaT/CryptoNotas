# Firmas digitales Ed25519 (mitigación A08:2025)

Módulo: `internal/crypto/firma.go` (+ `permisos_unix.go` / `permisos_windows.go`).
Pruebas: `internal/crypto/firma_test.go`.

## 1. Diagnóstico del módulo existente

| Aspecto | Dónde | Cómo funciona |
|---|---|---|
| Clave AES | `crypto.go` → `Cifrar` | 32 bytes aleatorios con `crypto/rand` (AES-256) |
| Cifrado | `crypto.go` → `Cifrar` / `Descifrar` | AES-256-GCM con nonce aleatorio de 12 bytes; GCM autentica el contenido |
| Hash | `crypto.go` → `HashSHA256` | SHA-256 en hexadecimal |
| Guardado | `artefactos.go` → `GuardarArtefactos` | `log.enc`, `clave.bin`, `nonce.bin`, `log.enc.sha256` con permisos 0600 |
| Recuperación | `artefactos.go` → `CargarArtefactos`, `DescifrarYComparar` | lee de disco, descifra y compara hashes |
| Punto de integración Ed25519 | `artefactos.go` → `GuardarManifiestoYFirma` y `VerificarFirmaAntesDeDescifrar` | firman el manifiesto y lo verifican **antes** de descifrar |

## 2. API (nombres definitivos para Laura y Leandro)

```go
GenerarParClaves() (ed25519.PublicKey, ed25519.PrivateKey, error)
FirmarManifiesto(manifiesto []byte, clavePrivada ed25519.PrivateKey) ([]byte, error)
VerificarFirma(manifiesto, firma []byte, clavePublica ed25519.PublicKey) error
GuardarClaves(clavePublica, clavePrivada, directorio string) error
CargarClavePublica(ruta string) (ed25519.PublicKey, error)
CargarClavePrivada(ruta string) (ed25519.PrivateKey, error)
```

Errores comparables con `errors.Is`: `ErrClavePrivadaInvalida`, `ErrClavePublicaInvalida`,
`ErrFirmaInvalida`, `ErrManifiestoVacio`.

Compatibilidad con el código ya integrado (no hay que cambiar `ui.go`):

- `FirmarManifiesto` mantiene la misma firma que antes; ahora valida la clave y rechaza manifiestos vacíos.
- `VerificarFirmaManifiesto` (bool) sigue existiendo y delega en `VerificarFirma`.
- `GenerarClavesEd25519` sigue existiendo y delega en `GenerarParClaves`.
- `CargarOCrearClaves` ahora usa `GuardarClaves` / `Cargar*` (mismos nombres de archivo y formato).
- Se eliminó el `GuardarClaves(rutaPrivada, rutaPublica, ...)` anterior, que no lo usaba nadie y chocaba con el nombre acordado.

## 3. Cómo generar y cargar claves

```go
pub, priv, err := crypto.GenerarParClaves()
err = crypto.GuardarClaves(pub, priv, "claves")   // crea claves/privada_ed25519.key y claves/publica_ed25519.pub

priv, err := crypto.CargarClavePrivada("claves/privada_ed25519.key")
pub, err  := crypto.CargarClavePublica("claves/publica_ed25519.pub")
```

- Formato: bytes crudos (64 la privada, 32 la pública).
- `GuardarClaves` no sobrescribe, rechaza `salida/` y `output/`, y si falla al escribir la pública borra la privada recién creada.
- Permisos: `chmod 0600` en Linux/macOS; en Windows se usa `icacls` (quita herencia y deja control total solo al usuario actual), porque `0600` por sí solo no protege con NTFS.
- `.gitignore` excluye `claves/`, `*.key`, `*.pub`, `*.bin`.

## 4. Cómo firmar y verificar

```go
priv, err := crypto.CargarClavePrivada(rutaPrivada)
firma, err := crypto.FirmarManifiesto(manifiestoBytes, priv)
err = os.WriteFile(rutaFirma, firma, 0o600)

pub, err := crypto.CargarClavePublica(rutaPublica)      // clave pública CONFIABLE
manifiestoBytes, err := os.ReadFile(rutaManifiesto)     // los mismos bytes, sin re-serializar
firma, err := os.ReadFile(rutaFirma)
if err := crypto.VerificarFirma(manifiestoBytes, firma, pub); err != nil {
    return err // detener: no descifrar
}
```

Regla acordada con Laura: se firman los **bytes exactos** que se guardan en `manifiesto.json`.
Nunca se vuelve a serializar el JSON al verificar (`TestFlujoManifiestoReal` lo comprueba).

## 5. Sustentación

1. **¿Qué es Ed25519?** Un esquema de firma digital de curva elíptica (Curve25519). Firma y verifica rápido, con claves de 32 bytes y firmas de 64.
2. **Pública vs. privada:** la privada firma y debe permanecer secreta; la pública verifica y puede distribuirse. Desde la pública no se puede obtener la privada.
3. **Cómo funciona:** se firma el manifiesto (que contiene el hash del archivo cifrado) con la clave privada; quien tenga la clave pública confiable comprueba que la firma corresponde a esos bytes.
4. **Si se modifica el archivo o el manifiesto:** el hash de `log.enc` deja de coincidir con el del manifiesto, o la firma deja de corresponder al manifiesto; en ambos casos la verificación falla y el proceso se detiene antes de descifrar.
5. **Relación con A08:2025 (fallos de integridad de software y datos):** sin firma, un atacante podría reemplazar archivo y manifiesto a la vez. Con Ed25519 solo puede hacerlo quien tenga la clave privada, y la autenticidad se comprueba con una clave pública confiable.

> Limitación a mencionar: si un atacante puede reemplazar también la clave pública que usa el verificador, la protección se pierde. Por eso la pública debe distribuirse por un canal confiable.
