# Dependency-Check en línea

Aplicación web que ejecuta **OWASP Dependency-Check** en un servidor para que cualquier persona suba su proyecto desde el navegador y vea las vulnerabilidades conocidas (CVE) de sus dependencias.

## Cómo funciona

1. Al iniciar, el servidor descarga la base de vulnerabilidades del NIST (NVD).
2. El usuario sube un `.zip` de su proyecto, un `.jar`/`.war`, un `package-lock.json`, `pom.xml` o `composer.lock`.
3. El servidor ejecuta `dependency-check.sh` sobre el archivo.
4. La página muestra un resumen por severidad y enlaza al reporte HTML oficial.

## Estructura

```
server.js            Backend Express que recibe archivos y ejecuta Dependency-Check
Dockerfile           Imagen oficial de Dependency-Check + Node.js
public/index.html    Página
public/styles.css    Estilos
public/app.js        Lógica del navegador
ejemplo-vulnerable/  Proyecto con librerías vulnerables para probar
```

## 1. Obtener la API key de NVD (gratis)

Solicítala en https://nvd.nist.gov/developers/request-an-api-key. Sin ella la primera descarga de la base puede tardar horas; con ella, unos 10 a 20 minutos.

## 2. Desplegar en Railway

1. Sube esta carpeta a un repositorio de GitHub.
2. En Railway: **New Project → Deploy from GitHub repo** y elige el repositorio. Railway detecta el `Dockerfile`.
3. En **Variables**, agrega `NVD_API_KEY` con tu clave.
4. En **Settings → Networking**, genera un dominio público. Ese es el enlace para compartir.
5. (Recomendado) Agrega un **Volume** montado en `/usr/share/dependency-check/data` para no descargar la base NVD cada vez que el servidor se reinicie.

El servicio necesita al menos 2 GB de RAM.

## 3. Probar en local (opcional, requiere Docker)

```bash
docker build -t dc-online .
docker run -p 3000:3000 -e NVD_API_KEY=tu_clave dc-online
```

Abre http://localhost:3000 y sube `ejemplo-vulnerable.zip`.

## Medidas de seguridad incluidas

- Solo se aceptan extensiones permitidas y archivos de hasta 20 MB.
- Protección contra **Zip Slip** (rutas como `../../`) y **zip bombs** (límite de 100 MB descomprimido).
- Los nombres de archivo y de proyecto se limpian antes de usarse.
- Se usa `execFile` en lugar de `exec`, así los datos del usuario nunca pasan por una shell (evita inyección de comandos).
- El código subido se borra después del análisis.
- Los resultados se pintan con `textContent` para evitar XSS.
