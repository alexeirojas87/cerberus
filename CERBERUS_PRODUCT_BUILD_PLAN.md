# Cerberus — Plan de construcción del producto (desde 0)

> **Propósito de este documento.** Es un plan de ingeniería por etapas, autocontenido, para
> construir **Cerberus** como producto independiente: un cortafuegos de datos sensibles (secretos
> + PII) para el tráfico hacia LLMs. Está escrito para que un agente (o un equipo) lo pueda
> ejecutar desde cero, incorporando la experiencia que ya acumulamos con la implementación previa
> de Cerberus en C# dentro del LLM Gateway.
>
> **Estado:** propuesta de diseño + plan. El estado de cada decisión (confirmada o pendiente) se
> lleva en §9; las pendientes deben cerrarse antes de la fase que las consume.

---

## 0. Visión en una frase

Cerberus evita que secretos (API keys, tokens, credenciales) y datos personales (PII) salgan hacia
cualquier LLM — tanto si se usa **por API** (server-side) como si se usa a través de **agentes de
coding locales** (Claude Code, Codex, opencode, pi, Cursor, etc.) — **sin que el secreto salga
nunca de la máquina del cliente** y añadiendo latencia despreciable al flujo.

### Posicionamiento

- **No** competimos como "otro guardrail de API LLM" (mercado ya poblado: Lakera, Prompt Security,
  Nightfall, HiddenLayer, LiteLLM guardrails, Cloudflare AI Gateway…).
- **Sí** atacamos el hueco menos cubierto: **DLP en la capa del agente de coding**. Un dev con
  Claude Code puede mandar `.env`, dumps de DB o código propietario al modelo y **ninguna DLP
  corporativa lo ve**, porque no pasa por el gateway de la empresa. Los escáneres clásicos
  (GitGuardian, TruffleHog, gitleaks) miran el repo/commits, no el *egress* hacia el LLM.
- Estrategia de confianza: **open-core + self-hosted**. "Tus secretos nunca salen de tu máquina"
  es a la vez requisito técnico y argumento de venta.

---

## 1. Experiencia incorporada (aprendizajes del Cerberus C# actual)

El motor previo vive en `src/Cerberus.Module/` del repo `ia-agentic-orchestation`. **Qué reutilizar
conceptualmente y qué corregir:**

### Reutilizar (funcionó bien)

- **Reglas 100% declarativas en JSON** (hoy `shared/cerberus-detection-rules.json`, v2.0.0). Cada
  regla: `flag`, `optionGate`, `severity`, `action`, `hashNormalization`, `contextKeywords`,
  `minLength`/`maxLength`, `allowedExamples`, `patterns` (regex), `validators`. **Es un buen
  esquema — se conserva casi tal cual.**
- **Validadores enchufables** (ej. Luhn para tarjetas) para bajar falsos positivos.
- **Constraints declarativas** (`contextKeywords` + `minLength`/`maxLength` + `allowedExamples`)
  para reducir ruido sin código.
- **Gates por categoría** (`BlockOnSecrets` / `BlockOnPersonalData`) → generalizar a categorías
  arbitrarias.
- **Audit writer + alertas de alto riesgo** como caminos **asíncronos y no bloqueantes** (nunca en
  la ruta crítica del request).

### Corregir (errores a NO repetir)

1. **`action` por regla se ignoraba.** El JSON tenía `"action": "block"` pero el motor devolvía
   siempre allow/block global. → **El nuevo motor DEBE honrar `action` por regla:
   `block | redact | warn | allow`.**
2. **Solo bloqueaba, no redactaba.** El resultado era un veredicto + flags, nunca un payload
   reescrito. → **La redacción es ciudadana de primera clase desde el día 1**: el motor devuelve el
   texto con los secretos reemplazados, no solo el veredicto.
3. **Acoplamiento al dominio.** `CerberusScanRequest` cargaba `AgentId`, `PbiId`, `CorrelationId`.
   → **El request de scan es genérico**: texto + metadata/labels arbitrarios. Nada de IDs de
   dominio en el core.
4. **`Task.Run(...).GetAwaiter().GetResult()` (sync-over-async) en el hot path.** → **La ruta de
   escaneo es verdaderamente no bloqueante y sin locks globales.**
5. **Regex .NET = backtracking = riesgo de ReDoS.** Un escáner que corre regex sobre cada request
   es un blanco perfecto de ReDoS. → **Motor de regex de tiempo lineal** (Rust `regex` crate /
   RE2 / Vectorscan). Ver §3.
6. **Acoplado a Mongo/Teams.** → Almacenamiento y notificaciones detrás de interfaces; el core no
   sabe de la infraestructura concreta.

---

## 2. Los dos modos de uso (eje central del diseño)

Esta división es la columna vertebral del producto. Interceptación, despliegue y config **difieren**
en cada modo, pero **comparten el mismo motor de detección/redacción**.

### Modo A — LLM vía API (server-side, centralizado)

- **Quién:** un backend/servicio que llama a un LLM (OpenAI, Anthropic, Gemini, modelos locales,
  cualquiera).
- **Dónde vive Cerberus:** como **reverse proxy** desplegable en la infra del cliente (contenedor,
  sidecar, o servicio). El backend apunta su base URL al proxy.
- **Config:** centralizada, una política para toda la org.
- **Despliegue:** Docker/Helm, self-hosted. Multi-tenant opcional (Pro).

### Modo B — LLM vía agentes locales (client-side, por developer)

- **Quién:** un dev corriendo Claude Code / Codex / opencode / pi / Cursor en su laptop.
- **Dónde vive Cerberus:** como **daemon/CLI local** ("Cerberus Local"), un binario único.
- **Interceptación:** el agente apunta su base URL a `localhost:<puerto>` (reverse proxy local).
- **Config:** **cero-config para arrancar** (rule packs por defecto). `cerberus init` autodetecta
  los agentes instalados y ajusta sus variables de entorno.
- **Distribución:** `brew install`, script `curl | sh`, **instalador Windows (winget/MSI)**, binario
  descargable. Soporta **macOS, Linux y Windows**.

```mermaid
flowchart LR
  subgraph ModoB["Modo B — Agentes locales (laptop del dev)"]
    CC[Claude Code] --> CL
    CX[Codex] --> CL
    OC[opencode / pi / Cursor] --> CL
    CL["Cerberus Local (daemon/CLI)"] -->|payload redactado| UP1[(Proveedor LLM)]
    CL --> ST1[(Store local SQLite)]
  end
  subgraph ModoA["Modo A — API (infra del cliente)"]
    BK[Backend / servicio] --> CP
    CP["Cerberus Proxy (reverse proxy)"] -->|payload redactado| UP2[(Proveedor LLM)]
    CP --> ST2[(Store / telemetría)]
  end
```

> **Decisión de MVP (confirmada):** se arranca por el **proxy universal** que sirve a los dos modos
> con el mismo motor. Los **hooks nativos por herramienta** (ej. `PreToolUse` de Claude Code) quedan
> para la **segunda ronda / post-GA** (ver backlog en §8), no comprometidos en el MVP. El proxy
> universal ya cubre Claude Code, Codex, opencode, pi y API directa porque todos permiten override
> de base URL.

### Modos de interceptación (tradeoff clave para "simple de configurar")

| Modo | Cómo | Ventaja | Costo |
|---|---|---|---|
| **Reverse proxy (base-URL override)** | El cliente apunta `*_BASE_URL` a Cerberus | Limpio, sin tocar TLS, sin certificados | Requiere que la tool soporte base URL (la mayoría sí) |
| **Forward proxy + CA local (MITM)** | Cerberus intercepta todo el egress TLS con un cert local de confianza | Universal, atrapa tools que hardcodean endpoint | Instalar un CA cert (fricción + preocupación de seguridad) — choca con "simple" |

> **Regla de diseño:** el **reverse proxy con base-URL override es el default** (encaja con "simple
> de configurar"). El modo MITM es **opt-in avanzado** para casos que hardcodean el endpoint. No se
> instala ningún CA cert sin acción explícita del usuario.

---

## 3. Decisión de stack / lenguaje

Requisito duro del owner: **rápido, latencia despreciable en el flujo con los LLMs**. Además:
binario único (instalación simple en laptops y en infra), motor de regex sin ReDoS.

### Investigación (2026)

- **Rust / Pingora** (framework de proxy de Cloudflare): ~70% menos CPU que el stack Nginx previo,
  **sin GC → latencia de cola predecible**, 40T+ req/mes en producción. En benchmarks 2026 Rust da
  ~40% menos latencia que Go en reescrituras de proxy; la ventaja viene precisamente de **no tener
  pausas de GC**, que es lo que más duele en un proxy.
- **Vectorscan** (fork portable BSD-3 de Intel Hyperscan): matchea **decenas de miles de regex
  simultáneamente en una sola pasada** sobre el stream de datos (pensado para DPI). Bindings desde
  Rust/C++. Ideal para escanear cientos de patrones de secretos por request sin iterar regla a
  regla.
- **Go**: excelente para proxies y muy productivo; su `regexp` estándar es RE2 (**tiempo lineal, sin
  ReDoS** — una ventaja real para un escáner). Pierde algo en latencia de cola por el GC.
- **.NET/C#** (lo que ya tenemos): YARP es buen reverse proxy y reusaríamos el JSON de reglas, pero
  el regex de .NET hace backtracking (ReDoS) y el footprint para distribuir a laptops es mayor
  (aunque AOT ayuda). El owner explícitamente abrió la puerta a otro lenguaje.

### Recomendación

| Componente | Lenguaje recomendado | Por qué |
|---|---|---|
| **Proxy + motor de detección/redacción (hot path)** | **Rust** | Sin GC → latencia de cola predecible; binario estático único (instala fácil en laptop e infra); `regex` crate y Vectorscan dan matching de tiempo lineal (sin ReDoS); base sólida con Pingora/`hyper`/`tower`. |
| **Dashboard + API de configuración** | **TypeScript + React** (backend en el mismo binario Rust vía API embebida, o un servicio Node aparte) | Ecosistema de UI maduro; no está en el hot path, así que el lenguaje no es crítico. |
| **Rule packs** | Datos (JSON/YAML versionado y firmado) | Agnóstico de lenguaje; se cargan y compilan en runtime. |

**Alternativa pragmática:** si la velocidad de desarrollo y la facilidad de contratación pesan más
que el último tramo de latencia de cola, **Go** es defendible (binario único, RE2 sin ReDoS,
ecosistema de proxy enorme). **Dado que "no añadir latencia" es requisito duro explícito, la
recomendación principal es Rust.**

> ✅ **DECISIÓN CONFIRMADA: Rust** para el proxy + motor (hot path). Go queda solo como referencia
> histórica de la alternativa evaluada. El resto del plan asume Rust.

---

## 4. Arquitectura del sistema

Mismo núcleo para los dos modos; cambia solo la capa de red y de despliegue.

```mermaid
flowchart TB
  IN[Request entrante del cliente/agente] --> ING[Capa de red<br/>reverse proxy / forward proxy]
  ING --> DEC[Decodificador de payload<br/>provider-agnostic]
  DEC --> DET[Motor de detección<br/>reglas + validadores + constraints]
  DET --> ACT[Motor de acción<br/>block / redact / warn / allow por regla]
  ACT -->|payload transformado| OUT[Forward al proveedor LLM]
  ACT -.->|async, no bloqueante| AUD[Audit + telemetría<br/>solo flags/hashes, nunca el secreto]
  ACT -.->|async| ALERT[Alertas<br/>Slack/Teams/webhook — Pro]
  AUD --> STORE[(Store: SQLite local / DB self-host)]
  STORE --> DASH[Dashboard + API de config]
  CFG[Config + rule packs] --> DET
  DASH -->|hot-reload| CFG
```

### 4.1 Capa de red

- **Reverse proxy** (default): escucha en un puerto local/infra, reenvía al upstream configurado.
  Soporta múltiples upstreams (uno por proveedor) o passthrough del `Host` original.
- **Streaming-aware:** para requests, se **buffea el body** (los prompts salientes son moderados) y
  se escanea **antes** de reenviar. Para respuestas en streaming (SSE/chunked), el escaneo
  token-a-token es más complejo → **fuera del MVP** (el egress de secretos ocurre en el request).
- **Política fail-open / fail-closed** configurable: si el motor falla, ¿se bloquea el request
  (seguro) o se deja pasar (disponible)? Default recomendado: **fail-closed para reglas `critical`,
  fail-open para el resto**, configurable.

### 4.2 Decodificador provider-agnostic (clave de la aclaración del owner)

**No se hardcodea el esquema de ningún proveedor.** Estrategia:

1. **Detección:** decodificar el body (JSON/text/multipart) y escanear **todo el contenido textual**
   en busca de patrones. Esto es agnóstico por construcción — funciona con OpenAI, Anthropic,
   Gemini, opencode, pi, modelos locales, cualquier esquema.
2. **Redacción:** reemplazar **in-place** las subcadenas que matchean (el valor del secreto),
   preservando la estructura JSON/bytes alrededor. Como solo se sustituye el valor detectado, no se
   corrompe el esquema.
3. **Adaptadores de esquema opcionales** (mejora, no requisito): para proveedores conocidos, acotar
   el escaneo a los campos de mensajes (`messages[].content`, etc.) para bajar falsos positivos.
   Son *plugins* opcionales; el baseline agnóstico siempre está.
4. **Providers custom / OpenAI-compatible son ciudadanos de primera clase.** No existe una "lista de
   providers soportados". Cualquier endpoint (NaN.Builders, vLLM/Ollama self-hosted, Groq,
   OpenRouter, Together, un provider opensource propio…) funciona registrando su *upstream* con una
   línea de config o `cerberus add-provider`. La API key del provider viaja en su header de auth y
   se trata como **credencial esperada del upstream** → **no se redacta**, solo se redactan los
   secretos que aparecen *dentro del contenido* del prompt. Ver Apéndice C para el escenario
   completo.

### 4.3 Motor de detección

Puerto del modelo declarativo del Cerberus C# (§1), con el `action` por regla honrado. Entrada:
`texto + metadata`. Salida: lista de `Finding { flag, category, severity, action, start, end,
hashedValue }`. **Nunca almacena ni loguea el valor crudo.**

- Compilación de patrones a un autómata multi-regex (Vectorscan) para una sola pasada.
- Validadores enchufables (Luhn, checksums, entropía Shannon para detectar claves genéricas de alta
  entropía).
- **Detección de bloques multilínea** (MVP): claves privadas PEM (`-----BEGIN PRIVATE KEY-----`),
  `id_rsa`, dumps de `.env` completos. Son de las fugas más graves y no las captura un regex de una
  sola línea.
- **Detector genérico por entropía como regla de primera clase** (MVP): dispara sobre strings de
  alta entropía próximos a keywords (`password=`, `token=`, `apikey=`) aunque no matcheen ningún
  patrón conocido — captura secretos propietarios.
- Constraints: `contextKeywords`, `minLength`/`maxLength`, `allowedExamples` (allowlist).
- Categorías/gates: `secrets`, `pii`, `internal-code`, personalizables.

### 4.4 Motor de acción

- Por regla: `block` (corta el request), `redact` (reemplaza y deja pasar), `warn` (deja pasar +
  audita), `allow` (ignora).
- **Redacción:** token de reemplazo configurable (`[REDACTED:flag]`), opción de **redacción
  reversible** (bóveda local que mapea token→valor para "des-redactar" respuestas, solo local y
  opt-in) vs **irreversible** (default, más seguro).
- Precedencia cuando varias reglas matchean el mismo span: `block > redact > warn > allow`.

### 4.5 Persistencia, audit y telemetría

- **Store local por defecto:** SQLite (Modo B). Self-host: Postgres/otro (Modo A).
- **Privacidad:** se guardan **flag, categoría, severidad, conteos, hash normalizado, timestamp,
  herramienta/proveedor** — **nunca el secreto**. Este es el corazón de la promesa de confianza.
- Todo el camino de audit/alertas es **async y no bloqueante**.

### 4.6 Config API + Dashboard

> **Principio rector: paridad total CLI ↔ dashboard.** Todo lo que se puede hacer por CLI/YAML
> (Apéndices A y B) DEBE poderse hacer también desde el dashboard, y viceversa. El dashboard y la
> CLI son dos frentes sobre la **misma Config API**; el YAML es solo el estado serializado. No hay
> acciones "solo CLI" ni "solo UI".

- **Estadísticas (con desglose por proveedor como requisito de primera clase):**
  - **Por proveedor:** volumen de requests, eventos (block/redact/warn), top flags, ratio de
    acciones y latencia añadida — todo filtrable y agrupable **por cada upstream** (anthropic,
    openai, nanbuilders, etc.).
  - Series temporales de eventos, top flags globales, desglose por **herramienta** (claude-code,
    codex, opencode…) además de por proveedor.
  - Comparativa entre proveedores (qué provider concentra más fugas potenciales).
- **Acciones de config (todas desde la UI):** alta/baja de **providers/upstreams** (incl. custom
  OpenAI-compatible), edición de la base URL local, toggles de categorías, activar/desactivar rule
  packs, edición de reglas propias, fijar `action` por regla, allowlists, política
  fail-open/closed, modo shadow/enforce (§4.7), y (Pro) alertas, equipos, SSO.
  - **Edición de reglas — split Free/Pro:** en **Free** se editan por formulario básico / YAML desde
    la UI; el **editor visual** avanzado (validación en vivo, test inline de la regla, versionado y
    políticas por equipo) es **Pro** (consistente con §7).
- **Triage de falsos positivos en un click:** desde cualquier evento del feed, un botón "marcar como
  falso positivo" lo añade a la allowlist al instante (clave para bajar el FP sin tocar YAML).
- **Hot-reload:** cualquier cambio de config (por UI o CLI) se aplica sin reiniciar el proxy.

### 4.7 Controles de adopción y operación (MVP)

Un DLP se desinstala si estorba. Estos controles existen para que Cerberus se **quede** instalado:

- **Shadow / monitor mode vs enforce.** Modo global de operación:
  - `shadow`: escanea y **registra** qué bloquearía/redactaría, pero **deja pasar todo intacto**.
  - `enforce`: aplica las acciones de verdad.
  - Patrón de rollout: se arranca en `shadow`, se ajustan falsos positivos con tráfico real, y recién
    entonces se pasa a `enforce`. Configurable global y por proveedor.
- **Break-glass / bypass auditado.** El dev puede forzar el envío de algo que Cerberus bloquearía,
  de forma consciente y **siempre registrada** (header `X-Cerberus-Bypass: <motivo>` o
  `cerberus allow-once`). Un bloqueo sin salida hace que desinstalen la herramienta; un bypass
  auditado mantiene el control sin frenar al dev.
- **Feedback al dev.** Cuando algo se redacta/bloquea, el dev **se entera** (notificación de
  escritorio, línea en el CLI y/o mensaje inyectado en la respuesta). La redacción silenciosa genera
  desconfianza y tickets de "¿por qué el modelo no vio mi config?".
- **Gestión de falsos positivos de primera clase.** Objetivo de precision/recall medido en continuo
  (§5) + triage de un click desde el dashboard (§4.6). El FP es el killer #1 de adopción.

---

## 5. Requisitos no funcionales

| Área | Requisito | Cómo se valida |
|---|---|---|
| **Latencia añadida** | ✅ Presupuesto oficial: p99 de overhead del proxy **< 3–5 ms** para prompts típicos (≤ 50 KB) | Benchmark con carga sintética + medición p50/p99 |
| **Throughput de escaneo** | Escanear ~100 KB contra cientos de patrones en **< 1 ms** (objetivo Vectorscan) | Micro-benchmark del motor |
| **Sin ReDoS** | Ningún patrón puede causar backtracking catastrófico | Motor de tiempo lineal + fuzzing de patrones |
| **Fuga cero de secretos** | El valor crudo nunca se persiste, loguea ni sale del proceso | Test de auditoría + revisión de logs |
| **Disponibilidad** | Política fail-open/closed explícita y configurable | Test de inyección de fallos |
| **Instalación simple** | Modo B: un comando; cero-config para el primer valor | Prueba de usuario en laptop limpia |
| **Precisión (falsos positivos)** | Objetivo de precision/recall por categoría, medido en continuo sobre los corpus; el FP es el killer #1 de adopción | Corpus de positivos/negativos + métricas por release |
| **Higiene de memoria** | Los valores de secretos se borran de memoria tras escanear (zeroization); nunca en logs ni en disco | Revisión de código + test de no-persistencia |
| **Integridad de release** | Binarios firmados y builds reproducibles; rule packs firmados | Verificación de firma en instalación/CI |
| **Multiplataforma** | Modo B en **macOS, Linux y Windows**; Modo A en contenedor | Matriz de CI por plataforma |

---

## 6. Modelo de datos (borrador)

```jsonc
// Regla (evolución del esquema actual; se añade "category" y se honra "action")
{
  "flag": "secret.openai_api_key",
  "category": "secrets",           // reemplaza el optionGate acoplado
  "severity": "critical",          // low | medium | high | critical
  "action": "redact",              // block | redact | warn | allow  <-- ahora SÍ se honra
  "hashNormalization": "trim",
  "contextKeywords": [],
  "minLength": 20, "maxLength": 128,
  "allowedExamples": [],
  "patterns": ["\\bsk-[A-Za-z0-9]{20,}\\b"],
  "validators": []                  // ej. ["luhn"], ["shannon-entropy>4.0"]
}

// Evento de audit (lo que se persiste — NUNCA el valor crudo)
{
  "id": "evt_...",
  "ts": "2026-08-16T12:00:00Z",
  "mode": "local",                  // local | api
  "tool": "claude-code",            // detectado o etiquetado
  "provider": "anthropic",
  "flags": ["secret.openai_api_key"],
  "counts": {"secret.openai_api_key": 1},
  "action_taken": "redact",
  "hashed_values": ["sha256:..."],  // para deduplicar sin revelar
  "severity": "critical"
}
```

---

## 7. Modelo Free / Pro

| **Free (open-core)** | **Pro / Team** |
|---|---|
| Proxy local + Modo API self-host | Rule packs premium curados y **auto-actualizados** (firmados) |
| Rule packs básicos | **Dashboard de auditoría** e históricos |
| block / redact / warn por regla | Editor visual de reglas + **políticas por equipo** |
| Config por JSON/YAML + toggles | SSO, multi-usuario, gestión centralizada |
| Store local (SQLite) | Alertas (Slack/Teams/webhook) |
| 1 usuario / local | Multi-tenant, on-prem con soporte SLA |
| Detección regex/validadores (secretos + PII estructurada) | **Detección de PII contextual por NER/NLP** (nombres, direcciones, organizaciones) — *futurible* |

> El *audit* y las *alertas* (que ya sabemos construir del Cerberus C#) caen naturalmente en Pro: es
> lo que compra un CISO. El dev individual solo quiere que "no se filtre mi `.env`" → eso es Free.

---

## 8. Plan por etapas

Cada fase: **objetivo · entregables · criterios de aceptación · experiencia incorporada · riesgos**.
Las fases 1–2 (motor) no tocan red; 3–4 (proxy) construyen los dos modos; 5–9 completan producto.

### Fase 0 — Fundaciones y spikes de validación

- **Objetivo:** cerrar decisiones de stack y probar los supuestos de latencia **antes** de construir.
- **Entregables:**
  - Stack ya confirmado (Rust, §3); lo que el spike decide es el **motor de matching**: Vectorscan
    vs `regex`/RE2 (§9 #3).
  - Scaffold de repo (workspace/monorepo), CI, linters, formato, harness de benchmark.
  - **Spike de escaneo:** cargar N patrones en Vectorscan (o `regex`/RE2) y medir tiempo de escaneo
    sobre payloads de 1/10/100 KB.
  - **Spike de proxy:** reverse proxy mínimo que reenvía y mide overhead p50/p99.
  - **Validar** el presupuesto de latencia (< 3–5 ms p99, §5) con datos del spike.
- **Aceptación:** spikes demuestran escaneo < objetivo y overhead de proxy < objetivo; motor de
  matching decidido y presupuesto de latencia validado por escrito.
- **Riesgos:** si Vectorscan no da el número, plan B = `regex` crate con set compilado + prefiltros.

### Fase 1 — Motor de detección (librería pura, sin red)

- **Objetivo:** portar el modelo declarativo de reglas a una lib pura `texto → findings`.
- **Entregables:**
  - Loader/compilador de reglas (JSON/YAML) con `category`, `severity`, `action`, constraints,
    validadores.
  - Validadores: Luhn, entropía Shannon, checksums comunes.
  - **Detección de bloques multilínea**: claves privadas PEM, `id_rsa`, `.env` completos.
  - **Detector genérico por entropía** como regla de primera clase (secretos sin patrón conocido).
  - **Corpus de prueba:** (a) secretos/PII reales-sintéticos que deben detectarse, (b) corpus de
    falsos positivos que NO deben disparar.
  - Migrar las reglas actuales de `shared/cerberus-detection-rules.json` como set base.
- **Aceptación:** paridad de detección con las reglas C# actuales + 0 ReDoS (fuzzing) + benchmark
  dentro de presupuesto + **precision/recall por categoría sobre el umbral objetivo de §5**.
- **Experiencia incorporada:** conservar `contextKeywords`/`minLength`/`allowedExamples`; **request
  genérico sin `AgentId`/`PbiId`**; **honrar `action` por regla**.
- **Riesgos:** falsos positivos en secretos genéricos de alta entropía → mitigar con `contextKeywords`
  + entropía + allowlists.

### Fase 2 — Motor de acción (block / redact / warn)

- **Objetivo:** convertir findings en un **payload transformado**, no solo un veredicto.
- **Entregables:**
  - Redacción in-place preservando estructura (bytes/JSON).
  - Token de reemplazo configurable; redacción reversible (bóveda local opt-in) vs irreversible
    (default).
  - Precedencia de acciones ante spans solapados.
  - **Break-glass / bypass auditado** (header `X-Cerberus-Bypass` o `cerberus allow-once`): deja
    pasar bajo override consciente y registra el evento con motivo (§4.7).
  - **Hook de feedback**: señal estructurada de "qué se redactó/bloqueó" para que la capa de red la
    muestre al dev (§4.7).
- **Aceptación:** dado un body con secretos, devuelve el body con cada secreto tratado según el
  `action` de su regla, sin corromper el JSON; round-trip de reversible funciona solo localmente; un
  bypass deja pasar el request y queda auditado.
- **Experiencia incorporada:** esto es exactamente lo que faltaba en el Cerberus C# (solo bloqueaba).
- **Riesgos:** corromper payloads binarios/multipart → tests de formato específicos.

### Fase 3 — Proxy core provider-agnostic (Modo A / API)

- **Objetivo:** reverse proxy que escanea/redacta el egress hacia **cualquier** proveedor.
- **Entregables:**
  - Reverse proxy con upstream(s) configurable(s), buffering de request, escaneo pre-forward
    (nota: en payloads grandes, evaluar escaneo incremental para no gastar el presupuesto de latencia).
  - **Shadow / enforce mode** (§4.7): global y por proveedor.
  - Decodificador agnóstico (§4.2) + adaptadores opcionales para OpenAI/Anthropic (bajar FP).
  - Política fail-open/closed.
  - Healthcheck, config por archivo, logs sin secretos.
- **Aceptación:** poniendo el proxy delante de un endpoint LLM real (cualquiera), un secreto en el
  prompt se redacta/bloquea según regla; **en `shadow` el mismo secreto se registra pero pasa
  intacto**; overhead p99 dentro de presupuesto; el request sigue siendo válido para el proveedor.
- **Riesgos:** streaming de respuestas → explícitamente fuera de MVP (documentarlo).

### Fase 4 — Cerberus Local (Modo B / agentes)

- **Objetivo:** el binario/daemon local para devs, con **cero-config** y setup de un comando.
- **Entregables:**
  - Reverse proxy local (localhost) reutilizando Fases 1–3.
  - `cerberus init`: autodetecta agentes instalados (Claude Code, Codex, opencode, pi…) y configura
    sus `*_BASE_URL`; `cerberus status`, `cerberus start/stop`.
  - Rule packs por defecto activos out-of-the-box.
  - Modo forward-proxy + CA local **opt-in** para tools que hardcodean endpoint.
  - **Soporte multiplataforma: macOS, Linux y Windows** (daemon + autodetección de agentes en las
    tres).
  - **Feedback al dev** cuando algo se redacta/bloquea (notificación de escritorio / línea en CLI).
- **Aceptación:** en una laptop limpia, un comando instala y arranca; corriendo Claude Code/Codex a
  través de Cerberus, un secreto en un prompt se redacta y el dev **recibe aviso** de que hubo
  redacción; sin config manual para el primer valor; verificado en **macOS, Linux y Windows**.
- **Experiencia incorporada:** "simple de configurar" = cero-config + autodetección, no un JSON de
  regex que el dev tenga que escribir.
- **Riesgos:** una tool que no soporte base URL ni respete el CA → documentar limitación y ofrecer
  MITM opt-in.

### Fase 5 — Persistencia, audit y telemetría

- **Objetivo:** registrar qué se protege, con **fuga cero** de secretos.
- **Entregables:** store SQLite (local) / DB (self-host); escritura async no bloqueante; esquema de
  eventos (§6); retención configurable.
- **Aceptación:** cada block/redact/warn queda registrado con conteos y hashes; auditoría de logs
  confirma que **ningún valor crudo** se persiste.
- **Experiencia incorporada:** reusar el patrón del audit writer C#, pero desacoplado de Mongo.

### Fase 6 — Config API + Dashboard

- **Objetivo:** UI para ver protección y **configurar todo** (paridad total con la CLI/YAML).
- **Entregables:**
  - **Config API** única (leer/escribir providers, reglas, packs, toggles, allowlists, políticas)
    con hot-reload del motor. La CLI y el dashboard son clientes de esta misma API.
  - **Estadísticas por proveedor** (requisito de primera clase): volumen, eventos, top flags, ratio
    de acciones y latencia **agrupables/filtrables por cada upstream**, más desglose por herramienta
    y series temporales.
  - Pantallas de config: alta/baja de providers (incl. custom OpenAI-compatible), base URL local,
    categorías, packs, reglas custom, `action` por regla, allowlists, fail-open/closed.
- **Aceptación:**
  1. El dashboard refleja eventos reales del store, **con vista y filtro por proveedor**.
  2. **Paridad CLI ↔ dashboard:** toda acción del Apéndice B tiene su equivalente en la UI y produce
     el mismo cambio de estado.
  3. Un cambio de config (por UI o CLI) se aplica sin reiniciar el proxy.
- **Nota:** Free = dashboard local básico; Pro = históricos largos, equipos, SSO, alertas.

### Fase 7 — Rule packs y actualizaciones

- **Objetivo:** paquetes curados y mantenidos (el valor que el dev no quiere escribir a mano).
- **Entregables:** packs versionados y **firmados** (AWS, GCP, Stripe, GitHub, Slack, PII-EU/GDPR,
  PII-US…); mecanismo de auto-update (Pro) con verificación de firma.
- **Aceptación:** los packs cargan y compilan; el update verifica firma y hace hot-reload; rollback
  posible.
- **Riesgos:** un pack con un patrón ReDoS → los packs pasan el mismo fuzzing que las reglas core.

### Fase 8 — Empaquetado, distribución y gating freemium

- **Objetivo:** que se instale fácil y que Free/Pro estén separados.
- **Entregables:** binario único + `brew`, script `curl | sh`, `.deb`/`.rpm`, **instalador Windows
  (winget/MSI)**; **binarios firmados** (notarización macOS, firma Windows); Docker/Helm para Modo
  A; sistema de licencias/entitlements que activa features Pro; telemetría **opt-in** con política de
  privacidad clara.
- **Aceptación:** instalación de un comando funciona en **macOS, Linux y Windows**; binarios con
  firma verificable; features Pro correctamente gated; self-host desplegable con Helm.
- **Riesgos:** el gating no debe romper la promesa open-core (el motor y el modo local básico
  quedan libres).

### Fase 9 — Hardening y GA

- **Objetivo:** listo para producción.
- **Entregables:** revisión de seguridad, fuzzing de ReDoS sobre todos los packs, load tests,
  pruebas de fail-safe, documentación de usuario y de operador, guía de "tus secretos no salen".
- **Aceptación:** pasa revisión de seguridad; load test sostiene el throughput objetivo; docs
  completas.

### Post-GA (backlog)

- **PII contextual por NER/NLP — `futurible` · feature Pro · NO forma parte del MVP.**
  - **Qué añade:** detección de PII que depende del contexto y que el regex no puede capturar —
    nombres de personas, direcciones postales, organizaciones. El regex/validadores del MVP cubren
    lo estructurado (emails, teléfonos, tarjetas, IBAN, SSN) y todos los secretos; NER cubre lo
    lingüístico.
  - **Por qué NO va en el MVP:** un modelo NER añade ms/decenas de ms → choca con el presupuesto
    duro de 3–5 ms p99. El MVP es **regex-only**.
  - **Enfoque cuando se construya (híbrido, estándar 2026):** regex rápido para lo estructurado +
    NER solo para PII contextual. Estrategias de latencia: (1) NER opt-in solo para categoría `pii`;
    (2) NER en modo `warn`/async fuera de la ruta crítica; (3) modelo pequeño **local** (referencia:
    Microsoft Presidio = recognizers regex + NER spaCy).
  - **Monetización:** se ofrece como capacidad **de pago (Pro)**, no en el tier Free.
- **Escaneo de respuestas en streaming** (SSE token-a-token).
- **Hooks nativos por herramienta** (`PreToolUse` de Claude Code, plugins de otros agentes) como
  integración premium más fina.
- **Escaneo de tool-calls / MCP** (secretos que salen en argumentos de herramientas del agente).

**Segunda ronda (confirmada por el owner, fuera del MVP):**

- **Decodificación antes de escanear** (base64 / hex / URL-encoded) para cerrar evasión.
- **Endpoint de métricas Prometheus + export a SIEM** (Splunk/Datadog/Elastic) — *Pro*.
- **Reporting de compliance** (GDPR/SOC2) exportable en CSV/PDF — *Pro*.
- **Alertas** (Slack/Teams/webhook) de eventos de alto riesgo — *Pro* (reusa el patrón del
  audit/alert notifier del Cerberus C#; aparece en el diagrama de §4 y en la config A.2, pero su
  construcción es post-MVP).
- **Detección de tamper / heartbeat**: seguridad sabe qué máquinas tienen Cerberus apagado — *Pro*.
- **SDK embebible**: el motor Rust vía FFI (bindings Python/Node/Go) para usar sin proxy —
  *futurible estratégico*.
- **Política por proveedor/ruta**: reglas distintas por upstream (estricto con externos, laxo con
  local).

---

## 8B · Protocolo de ejecución «Gauntlet» (OBLIGATORIO)

> Este protocolo **gobierna cómo se ejecuta cada fase de §8**. No es opcional. Ninguna funcionalidad
> se considera terminada hasta que **sobrevive el gauntlet**: se construye, se somete a una revisión
> crítica **con evidencia de prueba reproducible**, y si algo falla, **vuelve al loop** hasta pasar.

### 8B.1 — Principios (reglas duras)

1. **Nada se da por hecho sin evidencia.** Prohibido el veredicto "lo veo bien" / "debería
   funcionar" / "el código luce correcto". El único veredicto válido es: *"ejecuté **este comando** →
   obtuve **esta salida** → cumple/incumple **este criterio de aceptación**"*.
2. **Revisor independiente y adversarial.** El que revisa NO es el que construyó, arranca con
   contexto fresco, y su misión declarada es **romper la unidad**, no confirmarla.
3. **Si no se pudo ejecutar, es FAIL.** "No pude correr el test pero asumo que pasa" = FAIL. La
   ausencia de evidencia es una falla, no un empate.
4. **Fallo → loop.** Un FAIL reinicia el ciclo *de esa unidad*: se corrige con la evidencia del
   fallo en mano y se vuelve a revisar. Hasta PASS o escalar tras N intentos.
5. **La evidencia se archiva.** Cada unidad deja su Evidence Pack versionado en
   `evidence/<fase>/<unidad>.md` (o equivalente), citable y reproducible por cualquiera.

### 8B.2 — La unidad de trabajo

La **unidad** es la función/feature atómica que un subagente builder posee de punta a punta. Cada
entregable de §8 se descompone en unidades (ver tabla 8B.6). Toda unidad tiene:

- **Spec:** los criterios de aceptación de su fase que le aplican.
- **Owner builder:** el subagente que la implementa **y escribe sus pruebas automatizadas**.
- **Evidence Pack:** el artefacto de verificación (plantilla en 8B.5).

### 8B.3 — El loop del gauntlet (por unidad)

```mermaid
stateDiagram-v2
    [*] --> BUILD
    BUILD --> VERIFY: código + tests + notas de reproducción
    VERIFY --> PASS: evidencia demuestra TODOS los criterios
    VERIFY --> FAIL: falla ≥1 criterio o no se pudo ejecutar
    FAIL --> FIX: se entrega el Evidence Pack del fallo
    FIX --> VERIFY: re-verificación (independiente)
    PASS --> [*]: merge a la rama de la fase
    FAIL --> ESCALAR: tras N intentos sin pasar
    ESCALAR --> [*]: se detiene y se pide decisión humana
```

- **BUILD** — subagente builder (en **worktree aislado**, `isolation: worktree`, para no pisar a
  otros builders): implementa la unidad **y sus tests**, y escribe cómo reproducir la prueba.
- **VERIFY** — subagente(s) revisor(es) crítico(s), independientes: **ejecutan** (no solo leen)
  tests, la funcionalidad real, benchmarks y casos adversariales. Producen el Evidence Pack + un
  veredicto **PASS/FAIL** por criterio.
- **FIX** — si hay FAIL, un subagente fixer recibe el Evidence Pack del fallo (qué falló + cómo
  reproducirlo) y corrige. Vuelve a VERIFY con un revisor fresco.
- **ESCALAR** — tras `N` iteraciones (sugerido `N=3`) sin PASS, se detiene esa unidad y se escala a
  humano con todo el historial de intentos y evidencias.

> Para unidades de **alto riesgo** (latencia, seguridad, motor de detección) la verificación usa
> **panel de revisores diverso** (correctness + seguridad + performance) y se exige **mayoría** para
> el PASS, no un solo revisor.

### 8B.4 — Qué cuenta como evidencia (según el tipo de unidad)

| Tipo de unidad | Evidencia MÍNIMA obligatoria |
|---|---|
| Lógica / motor de detección | Salida de la suite de tests (conteos pass/fail), cobertura, **corpus FP/FN con precision/recall medido**, casos límite probados |
| Latencia / performance | Benchmark ejecutado + **números p50/p99 vs presupuesto 3–5 ms** + configuración del bench (tamaño de payload, nº de patrones) |
| Seguridad (ReDoS / zeroization / no-leak) | Fuzzing ejecutado + resultado; **grep de logs/disco demostrando 0 secretos**; prueba de que la memoria se limpia |
| Proxy / red | **Transcript real** (curl) del request atravesando el proxy: entrada con secreto → salida redactada; y en `shadow`, pass-through intacto + evento registrado |
| Break-glass / feedback | Transcript del bypass dejando pasar **y** quedando auditado; captura del aviso que recibe el dev |
| Dashboard / UI | **Screenshots** + pasos reproducibles; verificación de que los datos mostrados coinciden con el store (incl. desglose por proveedor) |
| Multiplataforma | **Matriz de CI** con la corrida verde en macOS, Linux y Windows |
| Empaquetado / firma | Log de instalación en cada OS + **verificación de firma** del binario |

### 8B.5 — Plantilla del Evidence Pack / veredicto (obligatoria)

```markdown
# Evidence Pack — <fase>/<unidad>
- Intento: <n>    Revisor: <id independiente del builder>    Veredicto: PASS | FAIL

## Criterios de aceptación (uno por fila)
| Criterio | Comando ejecutado | Salida (citada/adjunta) | Resultado |
|----------|-------------------|-------------------------|-----------|
| ...      | `cargo test ...`  | `... 128 passed; 0 failed` | ✅/❌ |

## Casos adversariales probados (intento de romper)
- <caso> → <resultado con evidencia>

## NFR aplicables
- Latencia: p99 = X ms (presupuesto < 3–5 ms) → ✅/❌  [adjuntar bench]
- Seguridad: <fuzzing/no-leak> → ✅/❌  [adjuntar salida]

## Si FAIL: qué falla y cómo reproducirlo
- <pasos exactos + salida del fallo>  → vuelve a BUILD/FIX
```

### 8B.6 — Descomposición en unidades por fase (qué subagentes levantar)

> El orquestador levanta **un builder por unidad** de la fase activa, luego **revisor(es) por
> unidad**. Respeta el DAG de §8: no arranca una fase hasta cerrar la anterior.

| Fase | Unidades (un builder + su gauntlet cada una) |
|---|---|
| **F0** | spike-escaneo, spike-proxy, scaffold+CI, presupuesto-latencia |
| **F1** | rule-loader, regex-compiler(Vectorscan), validators(luhn/entropy/checksum), multiline-blocks(PEM/.env), entropy-detector, constraints, corpus+precision/recall |
| **F2** | redaction-inplace, reversible-vault, action-precedence, break-glass, feedback-hook |
| **F3** | reverse-proxy-core, agnostic-decoder, schema-adapters, shadow/enforce, fail-policy, healthcheck+logs |
| **F4** | local-daemon, cerberus-init(autodetección), default-packs, mitm-opt-in, **windows-support**, dev-feedback-ux |
| **F5** | sqlite-store, event-schema, async-writer, retención, garantía-no-leak |
| **F6** | config-api, stats-por-proveedor, pantallas-config, fp-triage-1click, **paridad-CLI↔dashboard** |
| **F7** | pack-format, firma-de-packs, auto-update |
| **F8** | installers(brew/curl/deb/rpm/winget), binarios-firmados, licensing/entitlements, docker/helm, telemetría-opt-in |
| **F9** | security-review, redos-fuzz(todos los packs), load-test, failsafe, docs |

### 8B.7 — Gates de fase

1. Una **unidad** se cierra sólo con un Evidence Pack **PASS** → merge a la rama de la fase.
2. Una **fase** se cierra sólo cuando **todas** sus unidades pasaron **y** un revisor de
   **integración** corre las pruebas de integración de la fase con su propio Evidence Pack.
3. No se abre una fase dependiente hasta cerrar la anterior (DAG de §8).

### 8B.8 — Nota de orquestación

Este loop mapea directo a un patrón *pipeline + adversarial-verify + loop-until-pass*: por cada
unidad, `BUILD` → `VERIFY` (independiente, con evidencia) → si FAIL, `FIX` → `VERIFY`, hasta PASS o
escalar. Builders en worktrees aislados; revisores con contexto fresco; unidades de alto riesgo con
panel diverso y mayoría. El orquestador **no** avanza de fase con unidades en FAIL.

---

## 9. Riesgos y decisiones abiertas

| # | Tema | Estado |
|---|---|---|
| 1 | **Rust vs Go** para el core | ✅ CONFIRMADO: Rust |
| 2 | Presupuesto de latencia exacto (p99) | ✅ CONFIRMADO: < 3–5 ms; validar el número real en el spike de Fase 0 |
| 3 | Vectorscan vs `regex`/RE2 como motor de matching | Decidir en Fase 0 según spike |
| 4 | Redacción reversible: ¿se ofrece o solo irreversible? | ✅ Decidido: irreversible default, reversible opt-in local (se construye en Fase 2) |
| 5 | Escaneo de respuestas en streaming | Fuera de MVP; backlog |
| 6 | Modelo de licencias/entitlements para Pro | Definir antes de Fase 8 |
| 7 | Detección de PII por NER/NLP | ✅ Decidido: **futurible post-GA + feature Pro**, NO parte del MVP (regex-only en MVP por latencia) |

---

## 10. Glosario

- **Egress:** tráfico saliente (del cliente/agente hacia el proveedor LLM). Es donde se fuga el
  secreto.
- **Redacción:** reemplazar el valor sensible por un token, dejando pasar el resto del request.
- **ReDoS:** denegación de servicio por regex con backtracking catastrófico.
- **Vectorscan/Hyperscan:** motor de multi-regex de tiempo lineal para escaneo de alto rendimiento.
- **Reverse proxy (base-URL override):** el cliente apunta su base URL a Cerberus; sin tocar TLS.
- **Forward proxy + MITM:** Cerberus intercepta el egress TLS con un CA local; universal pero con
  fricción.
- **Rule pack:** conjunto curado y versionado de reglas de detección (ej. "AWS pack").

---

## 11. Referencias

- Pingora (Rust proxy de Cloudflare): https://www.blog.brightcoding.dev/2025/09/26/pingora-the-rust-framework-powering-the-next-generation-of-network-proxies-and-load-balancers/
- Rust vs Go latencia 2026: https://tech-insider.org/rust-vs-go-2026/
- Go vs Rust vs C++ reverse proxy (Pingora/Envoy/Traefik/Nginx): https://dev.to/kanywst/go-vs-rust-vs-c-deep-dive-into-reverse-proxy-performance-on-mac-pingoraenvoytraefiknginx-g40
- Vectorscan (fork portable de Hyperscan): https://github.com/VectorCamp/vectorscan
- LLM guardrails / DLP best practices (Datadog): https://www.datadoghq.com/blog/llm-guardrails-best-practices/
- LiteLLM guardrail providers: https://docs.litellm.ai/docs/guardrail_providers
- Coding Agent Guardrail – DLP for AI (Cloudanix, validación del nicho): https://www.cloudanix.com/coding-agent-guardrail

---

## Apéndice A — Configuración por modo (ejemplos)

> Regla de oro: **el YAML es solo el estado serializado de la Config API.** Todo esto se edita
> también desde la CLI (Apéndice B) y desde el dashboard (§4.6), de forma equivalente.

### A.1 — Modo B (agentes locales) — `~/.cerberus/config.yaml`

```yaml
listen: 127.0.0.1:8787
fail_mode: closed-on-critical      # bloquea si el motor falla en reglas critical

packs:                             # rule packs activos (Free trae los básicos)
  - secrets-core
  - pii-eu

categories:                        # toggles de alto nivel (los "gates" de antes)
  secrets: redact                  # action por categoría: redact | block | warn | allow
  pii:     warn

upstreams:
  anthropic:  { url: https://api.anthropic.com, expected_auth: header }
  openai:     { url: https://api.openai.com,    expected_auth: header }
  nanbuilders:{ url: https://api.nan.builders/v1, expected_auth: header }  # provider custom

allowlist:                         # falsos positivos conocidos que NO deben disparar
  - "sk-EXAMPLE-do-not-flag"

rules:                             # override fino por regla (opcional)
  secret.openai_api_key: { action: block }
```

### A.2 — Modo A (API, self-host) — `cerberus.yaml`

```yaml
listen: 0.0.0.0:8080
fail_mode: closed-on-critical

policy:                            # política ORG — el dev/servicio no la puede bajar
  packs: [secrets-core, secrets-cloud, pii-eu, pii-us]
  categories:
    secrets: block                 # server-side muchas orgs prefieren block
    pii:     redact

upstreams:
  openai:
    url: https://api.openai.com
    inject_key: { from: secret://vault/openai-prod }   # el backend NO necesita la key
  anthropic:
    url: https://api.anthropic.com
    inject_key: { from: secret://vault/anthropic-prod }

tenancy:                           # multi-tenant (Pro)
  mode: header
  header: X-Cerberus-Team

audit:
  store: postgres://cerberus-db/audit
  retention_days: 90

alerts:                            # Pro
  slack: { webhook: secret://vault/slack-secops, min_severity: high }
```

### A.3 — Los 3 niveles de configuración (Modo B)

- **Nivel 1 — cero-config:** `cerberus init` y listo (packs por defecto, `redact`).
- **Nivel 2 — toggles:** prender/apagar categorías y packs (`categories:` / `packs:`).
- **Nivel 3 — reglas propias:** regex propios y `action` por regla.

---

## Apéndice B — Referencia de comandos CLI

> **Paridad dashboard:** cada comando tiene su equivalente en el dashboard (§4.6). La columna
> "Dashboard" indica dónde vive esa acción en la UI.

### B.1 — Instalación y ciclo de vida (Modo B)

| Comando | Qué hace | Dashboard |
|---|---|---|
| `brew install cerberus` / `curl -fsSL https://get.cerberus.dev \| sh` | Instala el binario | — |
| `cerberus init` | Autodetecta agentes instalados, configura sus `*_BASE_URL`, activa packs por defecto y arranca el daemon | Wizard de onboarding |
| `cerberus start` / `stop` / `restart` | Controla el daemon local | Botón start/stop |
| `cerberus status` | Estado del daemon: puerto, upstreams, agentes conectados | Pantalla "Estado" |
| `cerberus mode <shadow\|enforce>` | Cambia el modo global de operación (shadow = solo registra, no aplica) | Toggle shadow/enforce |
| `cerberus allow-once [--reason <m>]` | Break-glass: deja pasar el próximo envío bloqueado, auditado | Botón "permitir una vez" |
| `cerberus doctor` | Diagnóstico: ¿daemon arriba?, ¿agentes apuntando bien?, ¿packs cargados? | Panel de diagnóstico |
| `cerberus version` / `cerberus upgrade` | Versión / actualizar binario | Aviso de versión |

### B.2 — Agentes y providers/upstreams

| Comando | Qué hace | Dashboard |
|---|---|---|
| `cerberus agents` | Lista agentes detectados y su estado de configuración | Pantalla "Agentes" |
| `cerberus agents wire <agent>` / `unwire <agent>` | Enruta / desenruta un agente a través de Cerberus | Toggle por agente |
| `cerberus providers` | Lista upstreams configurados | Pantalla "Providers" |
| `cerberus add-provider <name> --url <url> [--auth-header <h>]` | Registra un upstream custom (ej. NaN.Builders) e imprime la base URL local a pegar | Botón "Add provider" |
| `cerberus remove-provider <name>` | Elimina un upstream | Botón eliminar |

### B.3 — Reglas, categorías, packs y allowlist

| Comando | Qué hace | Dashboard |
|---|---|---|
| `cerberus packs list` | Lista rule packs disponibles/activos | Pantalla "Packs" |
| `cerberus packs enable <pack>` / `disable <pack>` | Activa/desactiva un pack | Toggle por pack |
| `cerberus packs update` | Actualiza packs (Pro, verifica firma) | Botón "Update packs" |
| `cerberus category set <secrets\|pii> --action <block\|redact\|warn\|allow>` | Fija la acción de una categoría | Selector por categoría |
| `cerberus rules list` | Lista reglas efectivas | Pantalla "Reglas" |
| `cerberus rules add --file <regla.yaml>` | Añade una regla propia | Editor de reglas |
| `cerberus rules set <flag> --action <...>` | Override de `action` por regla | Selector por regla |
| `cerberus allowlist add <valor>` / `list` / `remove <valor>` | Gestiona falsos positivos permitidos | Pantalla "Allowlist" |

### B.4 — Pruebas / dry-run (sin mandar nada al LLM)

| Comando | Qué hace | Dashboard |
|---|---|---|
| `cerberus scan <archivo>` | Escanea un archivo y muestra qué detectaría/redactaría, sin enviarlo | "Probar detección" |
| `cerberus test "<texto>"` | Igual pero con texto inline | Caja de prueba |

### B.5 — Observabilidad (con desglose por proveedor)

| Comando | Qué hace | Dashboard |
|---|---|---|
| `cerberus events [--provider <p>] [--tool <t>] [--since <t>]` | Lista eventos (block/redact/warn) filtrables | Feed de eventos |
| `cerberus stats [--by provider\|tool\|flag]` | Estadísticas agregadas; **`--by provider` da el desglose por upstream** | Gráficos del dashboard |
| `cerberus logs [-f]` | Logs del daemon (sin secretos) | Panel de logs |

### B.6 — Config y licencia

| Comando | Qué hace | Dashboard |
|---|---|---|
| `cerberus config show` / `edit` / `path` | Ver / editar / ubicar el archivo de config | Pantalla "Config" |
| `cerberus login` | Activa licencia / entitlements Pro | Pantalla "Cuenta" |
| `cerberus dashboard` | Abre la UI local (`http://localhost:8787/ui`) | — |

### B.7 — Modo A (API, operación / self-host)

| Comando | Qué hace |
|---|---|
| `helm install cerberus cerberus/cerberus -f values.yaml` | Despliega el proxy en Kubernetes |
| `helm upgrade cerberus ... -f values.yaml` | Aplica cambios de política/valores |
| `docker run -p 8080:8080 -v $PWD/cerberus.yaml:/etc/cerberus/config.yaml cerberus/cerberus` | Ejecución en contenedor |
| `cerberus validate -f cerberus.yaml` | Valida la config antes de desplegar (sintaxis, patrones sin ReDoS) |
| `cerberus reload` | Fuerza hot-reload de la config en una instancia corriendo |

> En Modo A la config se gestiona como IaC (archivo/ConfigMap) y por el dashboard central; los
> comandos interactivos de laptop del Modo B (init/agents/wire) no aplican.

---

## Apéndice C — Escenario: provider custom OpenAI-compatible (ej. NaN.Builders)

Caso: tienes un provider opensource con API estilo OpenAI y una API key, configurado en opencode.
**Funciona igual** porque el escaneo es agnóstico del esquema (§4.2, punto 4). Solo registras el
upstream.

**Antes** — opencode apuntando directo:
```jsonc
{
  "provider": {
    "nanbuilders": {
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://api.nan.builders/v1",
        "apiKey": "{env:NANBUILDERS_API_KEY}"
      }
    }
  }
}
```

**Después** — dos cambios:

1. Registras el upstream en Cerberus (o con el helper):
```bash
cerberus add-provider nanbuilders --url https://api.nan.builders/v1
# imprime: base URL local -> http://localhost:8787/nanbuilders
```
2. Cambias la `baseURL` de opencode a la ruta local:
```jsonc
{
  "provider": {
    "nanbuilders": {
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "http://localhost:8787/nanbuilders",
        "apiKey": "{env:NANBUILDERS_API_KEY}"
      }
    }
  }
}
```

**Notas:**
- Tu `NANBUILDERS_API_KEY` viaja en el header de auth → es **credencial esperada del upstream** y
  **no se redacta**; solo se redactan secretos dentro del contenido del prompt.
- Header no estándar: `cerberus add-provider nanbuilders --url ... --auth-header x-api-key`.
- Modelo 100% local (Ollama/LM Studio/vLLM en tu máquina): el secreto no sale del equipo, así que la
  protección es opcional; Cerberus igual sirve para **auditoría/visibilidad**.
- El upstream `nanbuilders` aparece automáticamente en las **estadísticas por proveedor** del
  dashboard (§4.6).
