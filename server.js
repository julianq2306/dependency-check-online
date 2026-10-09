// ===== 1. Importaciones =====
const express = require('express');           // servidor web
const multer = require('multer');             // recibir archivos subidos
const AdmZip = require('adm-zip');            // descomprimir .zip
const { execFile } = require('child_process');// ejecutar Dependency-Check
const crypto = require('crypto');             // ids únicos por análisis
const fs = require('fs');
const path = require('path');

// ===== 2. Configuración =====
const PORT = process.env.PORT || 3000;
const DC_PATH = process.env.DC_PATH || '/usr/share/dependency-check/bin/dependency-check.sh';
const NVD_API_KEY = process.env.NVD_API_KEY || '';
const TRABAJOS = path.join(__dirname, 'trabajos'); // archivos subidos (temporales)
const REPORTES = path.join(__dirname, 'reportes'); // reportes generados
const EXTENSIONES = ['.zip', '.jar', '.war', '.json', '.xml', '.lock'];
const MAX_DESCOMPRIMIDO = 100 * 1024 * 1024; // 100 MB, evita "zip bombs"

fs.mkdirSync(TRABAJOS, { recursive: true });
fs.mkdirSync(REPORTES, { recursive: true });

// Estado global: la base NVD debe estar lista y solo se analiza un proyecto a la vez
const estado = { baseLista: false, ocupado: false, mensaje: 'Actualizando la base de vulnerabilidades (NVD)' };

// Argumentos comunes para todas las ejecuciones
function argsBase() {
  const args = ['--disableOssIndex', '--disableAssembly'];
  if (NVD_API_KEY) args.push('--nvdApiKey', NVD_API_KEY);
  return args;
}

// ===== 3. Descargar/actualizar la base de vulnerabilidades al iniciar =====
function actualizarBase() {
  estado.baseLista = false;
  estado.mensaje = 'Actualizando la base de vulnerabilidades (NVD)';
  console.log('Actualizando base NVD...');
  execFile(DC_PATH, ['--updateonly', ...argsBase()], { maxBuffer: 50 * 1024 * 1024 }, (err, _out, stderr) => {
    if (err) {
      estado.mensaje = 'No se pudo actualizar la base de vulnerabilidades. Revisa los logs del servidor.';
      console.error(stderr || err.message);
      return;
    }
    estado.baseLista = true;
    estado.mensaje = 'Listo para analizar';
    console.log('Base NVD lista');
  });
}

// ===== 4. Configuración de subida de archivos =====
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, _file, cb) => {
      req.idTrabajo = crypto.randomUUID();
      const carpeta = path.join(TRABAJOS, req.idTrabajo);
      fs.mkdirSync(carpeta, { recursive: true });
      cb(null, carpeta);
    },
    // Conservamos el nombre original (Dependency-Check detecta "package-lock.json", "pom.xml"...)
    // pero quitamos cualquier ruta o carácter extraño
    filename: (_req, file, cb) => cb(null, path.basename(file.originalname).replace(/[^\w.\-]/g, '_'))
  }),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(EXTENSIONES.includes(ext) ? null : new Error('Tipo de archivo no permitido. Usa .zip, .jar, .war, package-lock.json, pom.xml o composer.lock'), true);
  }
});

// ===== 5. Descompresión segura =====
function descomprimir(rutaZip, carpeta) {
  const zip = new AdmZip(rutaZip);
  let total = 0;
  for (const entrada of zip.getEntries()) {
    // Zip Slip: ninguna entrada puede salir de la carpeta destino (ej: "../../etc/passwd")
    const destino = path.resolve(carpeta, entrada.entryName);
    if (!destino.startsWith(carpeta + path.sep)) throw new Error('El ZIP contiene rutas no permitidas');
    total += entrada.header.size;
    if (total > MAX_DESCOMPRIMIDO) throw new Error('El ZIP descomprimido supera los 100 MB');
  }
  zip.extractAllTo(carpeta, true);
  fs.unlinkSync(rutaZip);
}

// ===== 6. Resumir el reporte JSON para mostrarlo en la página =====
function resumir(rutaJson) {
  const reporte = JSON.parse(fs.readFileSync(rutaJson, 'utf8'));
  const conteo = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const dependencias = [];

  for (const dep of reporte.dependencies || []) {
    if (!dep.vulnerabilities || dep.vulnerabilities.length === 0) continue;
    const vulns = dep.vulnerabilities.map(v => {
      const severidad = (v.severity || 'LOW').toUpperCase();
      const clave = severidad === 'MODERATE' ? 'MEDIUM' : severidad;
      if (conteo[clave] !== undefined) conteo[clave]++;
      return {
        nombre: v.name,
        severidad: clave,
        puntaje: v.cvssv3?.baseScore ?? v.cvssv2?.score ?? null
      };
    });
    dependencias.push({ archivo: dep.fileName, vulnerabilidades: vulns });
  }

  return { totalDependencias: (reporte.dependencies || []).length, conteo, dependencias };
}

// ===== 7. Rutas =====
const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use('/reportes', express.static(REPORTES));

app.get('/api/estado', (_req, res) => res.json(estado));

app.post('/api/analizar', (req, res, next) => {
  // Revisamos antes de recibir el archivo
  if (!estado.baseLista) return res.status(503).json({ error: estado.mensaje });
  if (estado.ocupado) return res.status(429).json({ error: 'Hay otro análisis en curso. Intenta en unos minutos.' });
  next();
}, upload.single('archivo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Selecciona un archivo para analizar' });

  const id = req.idTrabajo;
  const carpeta = path.join(TRABAJOS, id);
  const salida = path.join(REPORTES, id);
  const proyecto = (req.body.proyecto || 'Proyecto').replace(/[^\w áéíóúñÁÉÍÓÚÑ\-]/g, '').slice(0, 50) || 'Proyecto';

  try {
    if (path.extname(req.file.filename).toLowerCase() === '.zip') descomprimir(req.file.path, carpeta);
  } catch (e) {
    fs.rmSync(carpeta, { recursive: true, force: true });
    return res.status(400).json({ error: e.message });
  }

  estado.ocupado = true;
  const args = [
    '--project', proyecto,
    '--scan', carpeta,
    '--out', salida,
    '--format', 'HTML',
    '--format', 'JSON',
    '--noupdate', // la base ya se actualizó al iniciar
    ...argsBase()
  ];

  execFile(DC_PATH, args, { timeout: 10 * 60 * 1000, maxBuffer: 50 * 1024 * 1024 }, (err, _out, stderr) => {
    estado.ocupado = false;
    fs.rmSync(carpeta, { recursive: true, force: true }); // borramos el código subido

    const rutaJson = path.join(salida, 'dependency-check-report.json');
    if (err && !fs.existsSync(rutaJson)) {
      console.error(stderr || err.message);
      return res.status(500).json({ error: 'Dependency-Check no pudo completar el análisis' });
    }
    res.json({
      id,
      proyecto,
      reporteUrl: `/reportes/${id}/dependency-check-report.html`,
      resumen: resumir(rutaJson)
    });
  });
});

// Errores de subida (tamaño, tipo de archivo)
app.use((err, _req, res, _next) => res.status(400).json({ error: err.message }));

// ===== 8. Arranque =====
app.listen(PORT, () => {
  console.log(`Servidor en http://localhost:${PORT}`);
  actualizarBase();
  setInterval(() => { if (!estado.ocupado) actualizarBase(); }, 24 * 60 * 60 * 1000); // una vez al día
});
