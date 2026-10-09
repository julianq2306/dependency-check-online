// ===== 1. Referencias a elementos de la página =====
const estadoEl = document.getElementById('estado');
const formulario = document.getElementById('formulario');
const inputArchivo = document.getElementById('archivo');
const zona = document.getElementById('zona');
const zonaTexto = document.getElementById('zona-texto');
const boton = document.getElementById('boton');
const resultado = document.getElementById('resultado');

const NOMBRES = { CRITICAL: 'Críticas', HIGH: 'Altas', MEDIUM: 'Medias', LOW: 'Bajas' };
const SEVERIDAD = { CRITICAL: 'Crítica', HIGH: 'Alta', MEDIUM: 'Media', LOW: 'Baja' };
let baseLista = false;

// ===== 2. Consultar si el servidor está listo =====
async function consultarEstado() {
  try {
    const res = await fetch('/api/estado');
    const estado = await res.json();
    baseLista = estado.baseLista;
    estadoEl.textContent = estado.ocupado ? 'Analizando otro proyecto, espera un momento' : estado.mensaje;
    estadoEl.className = 'estado' + (estado.baseLista ? ' listo' : '');
    actualizarBoton();
    if (!estado.baseLista) setTimeout(consultarEstado, 10000); // reintenta cada 10 s
  } catch {
    estadoEl.textContent = 'No hay conexión con el servidor';
    estadoEl.className = 'estado error';
  }
}

function actualizarBoton() {
  boton.disabled = !(baseLista && inputArchivo.files.length);
}

// ===== 3. Selección y arrastre del archivo =====
function mostrarArchivo() {
  const archivo = inputArchivo.files[0];
  zonaTexto.textContent = archivo ? archivo.name : 'Arrastra aquí tu archivo o haz clic para elegirlo';
  zona.classList.toggle('con-archivo', Boolean(archivo));
  actualizarBoton();
}

inputArchivo.addEventListener('change', mostrarArchivo);
zona.addEventListener('dragover', e => { e.preventDefault(); zona.classList.add('activa'); });
zona.addEventListener('dragleave', () => zona.classList.remove('activa'));
zona.addEventListener('drop', e => {
  e.preventDefault();
  zona.classList.remove('activa');
  inputArchivo.files = e.dataTransfer.files;
  mostrarArchivo();
});

// ===== 4. Enviar el archivo al servidor =====
formulario.addEventListener('submit', async e => {
  e.preventDefault();
  boton.disabled = true;
  boton.textContent = 'Analizando… puede tardar unos minutos';
  resultado.hidden = true;

  try {
    const res = await fetch('/api/analizar', { method: 'POST', body: new FormData(formulario) });
    const datos = await res.json();
    if (!res.ok) throw new Error(datos.error);
    pintarResultado(datos);
  } catch (err) {
    estadoEl.textContent = err.message || 'El análisis falló';
    estadoEl.className = 'estado error';
  } finally {
    boton.textContent = 'Analizar dependencias';
    actualizarBoton();
  }
});

// ===== 5. Mostrar resultados (textContent evita inyectar HTML: protección XSS) =====
function crear(etiqueta, texto, clase) {
  const el = document.createElement(etiqueta);
  if (texto !== undefined) el.textContent = texto;
  if (clase) el.className = clase;
  return el;
}

function pintarResultado({ proyecto, resumen, reporteUrl }) {
  const { conteo, dependencias, totalDependencias } = resumen;
  const total = Object.values(conteo).reduce((a, b) => a + b, 0);

  document.getElementById('titulo-resultado').textContent = total
    ? `${proyecto}: ${total} vulnerabilidades en ${dependencias.length} de ${totalDependencias} dependencias`
    : `${proyecto}: no se encontraron vulnerabilidades conocidas en ${totalDependencias} dependencias`;

  // Barra proporcional por severidad
  const barra = document.getElementById('barra');
  barra.replaceChildren();
  for (const sev of Object.keys(NOMBRES)) {
    if (!conteo[sev]) continue;
    const tramo = crear('span', undefined, sev.toLowerCase());
    tramo.style.width = `${(conteo[sev] / total) * 100}%`;
    barra.append(tramo);
  }

  // Conteo por severidad
  const lista = document.getElementById('conteo');
  lista.replaceChildren();
  for (const [sev, nombre] of Object.entries(NOMBRES)) {
    const li = crear('li');
    li.append(crear('strong', conteo[sev], sev.toLowerCase()), nombre);
    lista.append(li);
  }

  // Detalle por dependencia
  const detalle = document.getElementById('lista');
  detalle.replaceChildren();
  for (const dep of dependencias) {
    const bloque = crear('div', undefined, 'dependencia');
    bloque.append(crear('h3', dep.archivo));
    const ul = crear('ul');
    for (const v of dep.vulnerabilidades) {
      const li = crear('li');
      const puntaje = v.puntaje !== null ? ` (CVSS ${Number(v.puntaje).toFixed(1)})` : '';
      li.append(crear('span', SEVERIDAD[v.severidad] || v.severidad, v.severidad.toLowerCase()), `: ${v.nombre}${puntaje}`);
      ul.append(li);
    }
    bloque.append(ul);
    detalle.append(bloque);
  }

  document.getElementById('enlace-reporte').href = reporteUrl;
  resultado.hidden = false;
  resultado.scrollIntoView({ behavior: 'smooth' });
}

consultarEstado();
