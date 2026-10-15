He terminado la auditoría de seguridad de código (modo 2 de la skill) de `fixtures/invoice-app`. No modifiqué el repositorio: lo inspeccioné en solo lectura y la única ejecución de código del objetivo fue la app WSGI llamada en proceso por un arnés, dentro de un sandbox bwrap sin red, con entorno vacío, fuente de solo lectura, escritura solo en scratch y límites de CPU/memoria/procesos/tamaño/tiempo. No instalé paquetes. El informe lo tienes en HTML (en español).

## Resultado

**2 hallazgos confirmados (ambos High, CVSS-B 7.1) y 1 lead por validar.**

1. **Inyección SQL en `GET /search`** (`app.py:52-55`). El parámetro `q` se interpola en la sentencia con una f-string. Demostrado en sandbox como usuario `bob`: el payload `' OR 1=1 -- ` anula el filtro `owner_id` y devuelve las facturas de todos; un `UNION SELECT ... FROM users` vuelca la tabla de usuarios con los hashes PBKDF2. Lectura total (sqlite ejecuta una sola sentencia, sin escritura encadenada).
   Arreglo: consulta parametrizada — `WHERE owner_id = ? AND customer LIKE '%' || ? || '%'` con `(user["id"], q)`.
   Fuentes: OWASP ASVS 5.0.0 v5.0.0-1.2.4; CWE-89; OWASP Top 10:2025 A05:2025.

2. **IDOR en `GET /invoices/<id>`** (`app.py:39-42`). La consulta filtra solo por `id`, sin ligar `owner_id` al usuario autenticado. Demostrado: `bob` leyó la factura de `alice` (incluido el IBAN) por su id; la ruta hermana `GET /invoices` sí filtra por propietario, lo que confirma que el control existe pero falta aquí. Enumerable por id secuencial.
   Arreglo: añadir `AND owner_id = ?` con `user["id"]` (o devolver 404/403 si el propietario no coincide).
   Fuentes: OWASP ASVS 5.0.0 v5.0.0-8.2.2; CWE-639; A01:2025 y API1:2023.

**Por validar (sin severidad):** la app se sirve por HTTP plano con `wsgiref` enlazado a `127.0.0.1` (`app.py:62`); no hay TLS ni configuración de despliegue en el repo. Si se expone fuera de loopback sin un terminador TLS delante, las credenciales y los tokens viajarían en claro. Depende del despliegue (ASVS v5.0.0-12.2.1, CWE-319).

**Lo que está bien:** criptografía de contraseñas correcta (PBKDF2-SHA512 600k, sal aleatoria de 16 bytes, comparación en tiempo constante, tokens de 256 bits) y consultas parametrizadas en `/login` y `/invoices`.

**Notas de bastionado:** sesiones sin caducidad ni logout (CWE-613); sin límite de intentos en `/login`; oráculo de enumeración de usuarios por tiempo (el hash se omite para usuarios inexistentes); contraseña de demo compartida en `seed.py`; `wsgiref` no es para producción; minimizar campos devueltos (owner_id, IBAN).

**Aviso de método:** la verificación no fue independiente (no había sub-agentes aislados): un único agente hizo la caza y luego la validación, cerrando la caza antes de validar. Fue una pasada completa sobre todo el repo, pero eso no prueba la ausencia de otros fallos.

## Supuestos
- Nivel ASVS fijado en **L2** (API multiusuario con datos financieros; exposición externa no confirmada desde la fuente).
- Sin VCS en el objetivo: como referencia de versión usé el hash de contenido `sha256 9028bab1...`.
- Artefactos de skill (findings.json, reports, metadata) en inglés; el informe HTML en español, según tu regla de idioma.

## Ficheros (en outputs/)
- `security-report.html` — informe autocontenido en español (resumen, contexto, hallazgos con sus fuentes, leads por validar, cobertura y panel de prompt de mitigación con los High preseleccionados y botón Copiar).
- `findings.json` (3 registros, validado), `coverage-ledger.json` (9 unidades, validado), `run-metadata.json`.
- `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, `architecture.md`.
- `agents/h1/artifacts/evidence.txt` — traza de la prueba en sandbox.

Puedes abrir `security-report.html` en el navegador; el panel de mitigación genera un prompt listo para pegar en un agente de código.
