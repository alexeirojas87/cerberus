# Evidence Pack: Fase 1 — Revisión de Validators (REVISOR 1 — correctness)

**Revisor:** REVISOR 1 (correctness)
**Fecha:** 2026-08-17
**Worktree:** `cerberus-wt-f1-review-validators`
**Branch:** `f1/review-validators`

---

## Resumen de veredicto

| Criterio | Estado | Evidencia |
|---|---|---|
| 1. `cargo build --workspace` | ✅ PASS | Compila sin errores |
| 2. `cargo test -p cerberus-engine` (164 tests) | ✅ PASS | 115 unit + 38 adversarial + 11 integration — todos OK |
| 3. `cargo clippy -p cerberus-engine --all-targets -- -D warnings` | ✅ PASS | Sin warnings |
| 4. `cargo fmt --check` | ✅ PASS | Sin errores de formato |
| 5. Trait `Validator` bien definido | ✅ PASS | Interfaz minimalista y correcta: `fn validate(&self, value: &str) -> bool` |
| 6. Luhn: válido/inválido | ✅ PASS | "4111111111111111" → true; "1234567812345678" → false |
| 7. Luhn: edge cases | ✅ PASS | non-digits, muy corto, muy largo, solo no-dígitos, guiones, alfa alrededor |
| 8. Shannon entropy: cálculo correcto | ✅ PASS | "aaaa"=0.0, "ab"=1.0, unicode, patrones repetidos, empty=0.0 |
| 9. Shannon entropy: threshold > vs >= | ✅ PASS | `above(1.0)` falla en "ab", `at_least(1.0)` pasa en "ab" |
| 10. IBAN/checksum válido | ✅ PASS | BE y GB válidos; check digit inválido, lowercase, special chars, too short/long |
| 11. `get_validator` factory | ✅ PASS | luhn, checksum, shannon-entropy, shannon-entropy>N, shannon-entropy>=N → Some; nonexistent, empty → None |
| 12. `ValidatorRegistry.all_pass` | ✅ PASS | empty list → true; unknown → fail closed; mixed → fail closed; todos pasan → true |
| 13. Integración engine: validadores filtran findings | ✅ PASS | `make_finding()` ejecuta validadores después de regex match; si fallan, finding se descarta (`None`) |
| 14. Unknown validator fail-closed | ✅ PASS | `all_pass` con `"nonexistent"` retorna `false` |

**VEREDICTO FINAL: ✅ PASS**

---

## 1. Compilación y toolchain

```bash
$ rustc --version
rustc 1.97.1 (8bab26f4f 2026-07-14)

$ cargo build --workspace 2>&1 | tail -5
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 8.06s

$ cargo test -p cerberus-engine 2>&1 | grep "^test result:"
test result: ok. 115 passed; 0 failed   # unit tests
test result: ok. 38 passed; 0 failed    # adversarial (new)
test result: ok. 11 passed; 0 failed    # integration tests
test result: ok. 0 passed; 0 failed     # doc tests

$ cargo clippy -p cerberus-engine --all-targets -- -D warnings 2>&1 | tail -3
    Finished `dev` profile [unoptimized + debuginfo]

$ cargo fmt --check 2>&1 | wc -l
0   # sin salida = sin errores
```

---

## 2. Análisis del trait `Validator` (`validator.rs:15-18`)

```rust
pub trait Validator {
    fn validate(&self, value: &str) -> bool;
}
```

**Veredicto: ✅ Correcto.** Interfaz simple y genérica. Toma `&str` (no consume ownership), devuelve `bool`. Cero dependencias no esenciales. Las tres implementaciones (`LuhnValidator`, `ShannonEntropyValidator`, `ChecksumValidator`) cumplen correctamente el contrato.

---

## 3. LuhnValidator — análisis profundo

**Código:** `validator.rs:24-31`, implementación en `luhn_valid()` (líneas 206-228).

| Prueba | Input | Esperado | Real | Resultado |
|---|---|---|---|---|
| Visa válida | `"4111111111111111"` | true | true | ✅ |
| MasterCard válida | `"5555555555554444"` | true | true | ✅ |
| AmEx válida | `"378282246310005"` | true | true | ✅ |
| Número aleatorio | `"1234567812345678"` | false | false | ✅ |
| Todos ceros | `"0000000000000000"` | true | true | ✅ (degenerado pero matemáticamente correcto) |
| Con guiones | `"4111-1111-1111-1111"` | true | true | ✅ |
| Alfa alrededor | `"card 4111111111111111 here"` | true | true | ✅ |
| Solo 1 dígito | `"1"` | false | false | ✅ |
| 2 dígitos inválidos | `"12"` | false | false | ✅ |
| Solo no-dígitos | `"abcdef"` | false | false | ✅ |
| 160 dígitos (10x repet) | `"4111111111111111"*10` | true | true | ✅ |
| 14 dígitos válidos | `"12345678903555"` | true | true | ✅ |

**Detalle del algoritmo:** 
1. Filtra caracteres no-dígito (`filter(char::is_ascii_digit)`)
2. Requiere ≥ 2 dígitos
3. Invierte, duplica cada segundo dígito (posición impar en el iterador reversed), suma dígitos (para duplicados > 9, suma `d*2 - 9`)
4. Verifica que la suma total sea múltiplo de 10 (`sum.is_multiple_of(10)` — estabilizado en Rust 1.66)

**Veredicto: ✅ Correcto.** Implementación canónica sin errores.

---

## 4. ShannonEntropyValidator — análisis profundo

**Código:** `validator.rs:46-89`, función `shannon_entropy()` (líneas 185-199).

| Prueba | Input | Entropía esperada | Resultado |
|---|---|---|---|
| Vacío | `""` | 0.0 | ✅ |
| 1 carácter | `"x"` | 0.0 | ✅ |
| 2 iguales | `"aa"` | 0.0 | ✅ |
| 2 diferentes | `"ab"` | 1.0 | ✅ |
| Unicode (3 chars) | `"日本語"` | log₂(3) ≈ 1.585 | ✅ |
| Patrón repetido | `"abababababababab"` | 1.0 | ✅ |
| Larga baja diversidad | `"a"*10000 + "b"` | < 0.01 | ✅ |

**Fórmula:** H = -Σ p(c) · log₂ p(c), implementada con `p.mul_add(-p.log2(), acc)` que es numéricamente estable.

**Thresholds:**
| Prueba | Validator | Input | Esperado | Resultado |
|---|---|---|---|---|
| above(4.0) rechaza baja | `above(4.0)` | `"aaaa"` | false | ✅ |
| above(4.0) acepta alta | `above(4.0)` | `"J8sK4mL2pX9qR5vW1nB6tY3cD7fH0gA"` | true | ✅ |
| at_least(1.0) en frontera | `at_least(1.0)` | `"ab"` | true | ✅ |
| above(1.0) en frontera | `above(1.0)` | `"ab"` | false | ✅ |
| empty + above(0.0) | `above(0.0)` | `""` | false | ✅ (0.0 > 0.0 es falso) |
| empty + at_least(0.0) | `at_least(0.0)` | `""` | true | ✅ (0.0 >= 0.0 es verdadero) |

**Parseo de nombre:**
| Nombre | Resultado | Threshold |
|---|---|---|
| `"shannon-entropy"` | `Above(3.0)` | ✅ |
| `"shannon-entropy>4.5"` | `Above(4.5)` | ✅ |
| `"shannon-entropy>=4.5"` | `AtLeast(4.5)` | ✅ |
| `"shannon-entropy=4.0"` | `None` | ✅ (formato inválido) |
| `"shannon-entropy>"` | `None` | ✅ (threshold vacío) |
| `"shannon-entropy>abc"` | `None` | ✅ (no-numérico) |

**Veredicto: ✅ Correcto.** Cálculo de entropía correcto. Distinción > vs >= correcta. Parseo de nombres robusto.

---

## 5. ChecksumValidator (IBAN) — análisis profundo

**Código:** `validator.rs:94-101`, función `iban_valid()` (líneas 235-267).

| Prueba | Input | Esperado | Resultado |
|---|---|---|---|
| BE válido | `"BE68539007547034"` | true | ✅ |
| GB válido | `"GB29NWBK60161331926819"` | true | ✅ |
| Con espacios | `"BE68 5390 0754 7034"` | true | ✅ |
| Check digit inválido | `"BE68539007547035"` | false | ✅ |
| Minúsculas | `"be68539007547034"` | false | ✅ |
| Vacío | `""` | false | ✅ |
| Muy corto | `"DE123"` | false | ✅ |
| Muy largo (35+ chars) | `"DE89370400440532013000000000000000000000"` | false | ✅ |
| Caracteres especiales | `"BE68!5390?0754&7034"` | false | ✅ |
| No-ASCII | `"BE68😀39007547034"` | false | ✅ |

**Algoritmo:** Mod-97 (ISO 7064). Mueve primeros 4 caracteres al final, convierte A→10...Z→35, computa `n % 97`, resultado debe ser 1.

**Veredicto: ✅ Correcto.** Implementación completa y robusta.

---

## 6. Integración con engine (`engine.rs`)

En `make_finding()` (engine.rs:258-276):

```rust
let trimmed = raw_value.trim();
if !self.validators.all_pass(&rule.validators, trimmed) {
    return None;  // finding descartado
}
```

**Flujo:** `scan()` → regex match → `make_finding()` → `all_pass(validators, trimmed)` → si algún validador falla → `None` (finding se descarta).

| Prueba | Escenario | Resultado |
|---|---|---|
| Sin validators | Match se mantiene | ✅ |
| Luhn en número válido | Finding se mantiene | ✅ |
| Luhn en número inválido | Finding se descarta | ✅ |
| Shannon-entropy en alta entropía | Finding se mantiene | ✅ |
| Shannon-entropy en baja entropía | Finding se descarta | ✅ |
| Unknown validator | Fail closed — finding se descarta | ✅ |
| Múltiples validators (todos pasan) | Finding se mantiene | ✅ |
| Múltiples validators (uno falla) | Finding se descarta | ✅ |

**Veredicto: ✅ Correcto.** Los validators se ejecutan después del regex match. Si algún validador falla, el finding se descarta. Fail-closed para validators desconocidos.

---

## 7. Edge cases cubiertos por pruebas adversariales

Archivo: `crates/cerberus-engine/tests/adversarial_validators.rs` (38 tests nuevos)

**Categorías cubiertas:**
- **Luhn (12 tests):** Visa, MasterCard, AmEx, inválido, todos ceros, con guiones, alfa alrededor, single digit, dos dígitos, solo no-dígitos, muy largo, 14 dígitos
- **Entropía (11 tests):** single char, dos iguales, dos diferentes, unicode, patrón repetido, muy larga baja diversidad, rechazo/aceptación threshold, frontera at_least/above, empty+above/at_least
- **IBAN (10 tests):** BE, GB, espacios, check digit inválido, lowercase, empty, too short, too long, special chars, non-ASCII + checksum validator delegate
- **Factory/Registry (5 tests):** 11 nombres de get_validator, registry get, all_pass edge cases, all_pass múltiples validators

---

## 8. Conclusión

El módulo de validators cumple con todos los criterios de correctness para Fase 1:

- El trait `Validator` está correctamente definido
- `LuhnValidator` implementa el checksum ISO 7812 correctamente
- `ShannonEntropyValidator` calcula entropía correctamente con thresholds > y >=
- `ChecksumValidator` implementa IBAN mod-97 correctamente
- `get_validator` y `ValidatorRegistry` resuelven nombres correctamente y hacen fail-closed
- La integración con `engine.rs` ejecuta validators después del regex match y descarta findings que fallen
- 38 pruebas adversariales nuevas cubren edge cases no cubiertos por tests existentes

**VEREDICTO FINAL: ✅ PASS**