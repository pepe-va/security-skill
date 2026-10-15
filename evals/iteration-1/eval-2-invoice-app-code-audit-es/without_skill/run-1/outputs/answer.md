He revisado a mano todo el código de `invoice-app` y no está lista para usuarios reales: dos fallos permiten a cualquier usuario autenticado leer datos de otros clientes. Los dos se arreglan cambiando una o dos líneas.

Informe HTML: `evals/iteration-1/eval-2-invoice-app-code-audit-es/without_skill/outputs/informe-auditoria-invoice-app.html`

**Los dos fallos graves**
- **H-01, inyección SQL en `/search`** (`app.py:53-55`): el parámetro `q` se mete en la consulta SQL tal cual. Un usuario autenticado puede leer facturas de todos los clientes y también los hashes de contraseña. Se corrige con una consulta parametrizada; la corrección que propongo la he probado en una base de datos de prueba en memoria.
- **H-02, acceso a facturas ajenas en `GET /invoices/<id>`** (`app.py:41-42`): la consulta no comprueba quién es el dueño de la factura. Basta con cambiar el número de la URL para ver la factura de otro cliente, IBAN incluido. Se corrige añadiendo `AND owner_id = ?` a la consulta y devolviendo 404 si la factura no es del usuario.

**Otros problemas**
- **Media (3):**
  - Las sesiones no caducan y no hay forma de cerrar sesión.
  - El login no limita los intentos. Además, el cálculo del hash es costoso a propósito y el servidor atiende una petición cada vez, así que una ráfaga de intentos puede bloquear el servicio.
  - `wsgiref` es un servidor de desarrollo: sin TLS y sin tiempos de espera.
- **Baja (5):**
  - El cuerpo de `/login` se lee sin límite de tamaño.
  - Por el tiempo de respuesta se puede saber si un usuario existe.
  - El detalle de factura devuelve el IBAN completo y el identificador interno del dueño.
  - La base de datos guarda el IBAN sin cifrar, con permisos de lectura por defecto.
  - `seed.py` da la misma contraseña fija a todos los usuarios.
- **Informativa (3):** no se registran eventos de seguridad, faltan cabeceras de seguridad y las conexiones a la base de datos no se cierran.

**Lo que está bien hecho:**
- Las contraseñas se guardan con PBKDF2-SHA512 a 600 000 iteraciones, con sal por usuario.
- Los hashes se comparan con una función de tiempo constante.
- Los tokens de sesión son de 256 bits y aleatorios.
- El resto de consultas ya están parametrizadas.

Cada hallazgo del informe incluye el fichero y las líneas, el fragmento de código, el impacto, el código de la corrección y sus referencias (CWE, OWASP Top 10:2021, API Security Top 10:2023 y ASVS 4.0.3). El informe también trae un plan de corrección en tres fases.

**Cómo lo hice y qué he supuesto**
- Ha sido una revisión estática del código: no he arrancado la aplicación ni he hecho pruebas contra ella. El código es corto y los fallos no dependen de la configuración, así que la confianza en los resultados es alta.
- He valorado la gravedad como si la aplicación fuera a tener varios usuarios reales. Como demo local en `127.0.0.1`, el riesgo práctico es menor.
- No hay fichero de dependencias y el código solo usa la biblioteca estándar de Python, así que no había dependencias de terceros que revisar.
- No he modificado el repositorio: las huellas SHA-256 de los ficheros son las mismas antes y después, y van en el informe.
