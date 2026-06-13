/* ============================================================================
   AEGIS i18n — lightweight UI translation (English → Spanish)
   ----------------------------------------------------------------------------
   Display-only, exact-match string table applied to the DOM:
     • Skips SELECT/OPTION/INPUT/TEXTAREA/SCRIPT/STYLE entirely, so stored data
       values (severities, statuses, types) are NEVER altered — only how text
       is shown. Pills and tables that display stored values are translated
       visually; the underlying records stay in English.
     • A MutationObserver re-applies translations to dynamically rendered
       content (tables, drawers, modals) without touching app code.
     • Strings without a dictionary entry simply remain in English.
   Preference is per-device (localStorage 'aegis.lang'); change it in Settings.
   ============================================================================ */
(function (global) {
  'use strict';
  var LS_KEY = 'aegis.lang';
  function getLang() { try { return localStorage.getItem(LS_KEY) || 'en'; } catch (e) { return 'en'; } }

  var ES = {
    /* ---- shared chrome ---- */
    "Sign In": "Iniciar sesión",
    "⏻ Sign out": "⏻ Cerrar sesión",
    "⏻ Sign out ·": "⏻ Cerrar sesión ·",
    "⚙ Settings": "⚙ Configuración",
    "Settings": "Configuración",
    "Configuration": "Configuración",
    "Save": "Guardar",
    "Cancel": "Cancelar",
    "Delete": "Eliminar",
    "Edit": "Editar",
    "Add": "Añadir",
    "Search…": "Buscar…",
    "Loading…": "Cargando…",
    "Checking session…": "Verificando sesión…",
    "↻ Refresh": "↻ Actualizar",
    "Refresh": "Actualizar",
    "Export": "Exportar",
    "Import": "Importar",
    "Purge": "Purgar",
    "Operator": "Operador",
    "OPERATOR": "OPERADOR",
    "Passphrase": "Contraseña",
    "Confirm passphrase": "Confirmar contraseña",
    "Notes": "Notas",
    "Notes (optional)": "Notas (opcional)",
    "Latitude": "Latitud",
    "Longitude": "Longitud",
    "Type": "Tipo",
    "Status": "Estado",
    "Title": "Título",
    "Category": "Categoría",
    "Label": "Etiqueta",
    "Name": "Nombre",
    "Location": "Ubicación",
    "Country": "País",
    "Date": "Fecha",
    "Time": "Hora",
    "detecting…": "detectando…",
    "Field Security Operations": "Operaciones de seguridad en el terreno",

    /* ---- portal ---- */
    "Operations Console": "Consola de operaciones",
    "Open-Source Intelligence Shortcuts": "Accesos de inteligencia de fuentes abiertas",
    "↺ Defaults": "↺ Predeterminados",
    "Threat Watch": "Vigilancia de Amenazas",
    "Trip Command": "Comando de Viajes",
    "Analytic Workbench": "Estación de Análisis",
    "Workbench · Training": "Estación de Análisis · Entrenamiento",
    "Task List": "Lista de Tareas",
    "Security Feed": "Canal de Seguridad",
    "Situational Awareness": "Conciencia situacional",
    "Movement Planning": "Planificación de movimientos",
    "Analysis": "Análisis",
    "Training": "Entrenamiento",
    "Tasking": "Tareas",
    "OSINT Stream": "Flujo OSINT",
    "Worldwide threat & advisory tracking with duty-of-care personnel accountability and a live GEOINT map.": "Seguimiento mundial de amenazas y avisos con control de personal (deber de protección) y mapa GEOINT en vivo.",
    "Itinerary, lodging, and budget planning with a geospatial operating picture and printable travel brief.": "Planificación de itinerario, alojamiento y presupuesto con panorama geoespacial e informe de viaje imprimible.",
    "All-source reporting log, entity & link analysis, GEOINT, and Analysis of Competing Hypotheses — saved to the suite database.": "Registro de informes de todas las fuentes, análisis de entidades y vínculos, GEOINT y Análisis de Hipótesis en Competencia — guardado en la base de datos.",
    "Hands-on training sandbox preloaded with a fictional scenario for practicing tradecraft. Stored locally, separate from live data.": "Entorno de práctica con un escenario ficticio para ejercitar el oficio analítico. Se guarda localmente, separado de los datos reales.",
    "Lightweight personal tasking and pre-deployment checklists with subtasks and progress tracking.": "Tareas personales ligeras y listas de verificación previas al despliegue, con subtareas y seguimiento de progreso.",
    "Live open-source situational awareness — humanitarian, disaster, travel-advisory, health, and cyber sources in one stream.": "Conciencia situacional de fuentes abiertas en vivo — fuentes humanitarias, de desastres, avisos de viaje, salud y ciberseguridad en un solo canal.",
    "Defensive duty-of-care use only. Not for unlawful surveillance, targeting, or harm.": "Solo para uso defensivo de deber de protección. No para vigilancia ilegal, selección de objetivos ni daño.",
    "Non-Commercial & Ethical-Use License": "Licencia de uso no comercial y ético",

    /* ---- settings ---- */
    "Organization & Display": "Organización y presentación",
    "Suite name": "Nombre del sistema",
    "Organization / Unit": "Organización / Unidad",
    "Classification banner text": "Texto del banner de clasificación",
    "Shown top & bottom of every page. Set this to match your own handling caveat.": "Se muestra arriba y abajo en cada página. Ajústelo a su propia norma de manejo.",
    "Operator initials": "Iniciales del operador",
    "Home region (optional)": "Región base (opcional)",
    "Save Display Settings": "Guardar configuración",
    "Access & Passphrase": "Acceso y contraseña",
    "Current passphrase": "Contraseña actual",
    "New passphrase": "Nueva contraseña",
    "Confirm new": "Confirmar nueva",
    "Update Passphrase": "Actualizar contraseña",
    "OSINT Shortcuts": "Accesos OSINT",
    "↺ Restore Default Links": "↺ Restaurar enlaces predeterminados",
    "Data & Backup": "Datos y copias de seguridad",
    "⤓ Download Backup": "⤓ Descargar copia",
    "⤒ Restore (merge)": "⤒ Restaurar (combinar)",
    "⤒ Restore (replace all)": "⤒ Restaurar (reemplazar todo)",
    "Deployment": "Despliegue",
    "Upgrade to Secure Mode": "Actualizar a modo seguro",
    "Mode": "Modo",
    "Database driver": "Controlador de base de datos",
    "About & License": "Acerca de y licencia",
    "Reset This Device": "Restablecer este dispositivo",
    "Erase All Local AEGIS Data": "Borrar todos los datos locales de AEGIS",
    "SECURE mode — server + database": "Modo SEGURO — servidor + base de datos",
    "STANDALONE mode — local browser only": "Modo AUTÓNOMO — solo navegador local",
    "Authentication and all records are handled by the AEGIS server and stored in a shared database.": "La autenticación y todos los registros se gestionan en el servidor AEGIS y se guardan en una base de datos compartida.",
    "No server detected. Records and credentials live only in this browser. The login is a convenience lock, not a security boundary.": "No se detectó servidor. Los registros y credenciales viven solo en este navegador. El inicio de sesión es un candado de conveniencia, no una barrera de seguridad.",
    "Appearance & Language": "Apariencia e idioma",
    "Theme": "Tema",
    "Language": "Idioma",
    "🌙 Dark": "🌙 Oscuro",
    "☀ Light": "☀ Claro",
    "Per-device preferences stored in this browser. Spanish coverage focuses on navigation, forms, and buttons; long reference text remains in English.": "Preferencias por dispositivo guardadas en este navegador. La cobertura en español se centra en navegación, formularios y botones; los textos largos de referencia permanecen en inglés.",

    /* ---- security feed ---- */
    "Open-source situational awareness": "Conciencia situacional de fuentes abiertas",
    "Filter headlines…": "Filtrar titulares…",
    "All": "Todos",
    "Pulling sources…": "Obteniendo fuentes…",
    "No items match.": "No hay coincidencias.",
    "Live feed needs the server deployment": "El canal en vivo requiere el despliegue con servidor",
    "The aggregator pulls security and humanitarian sources through the AEGIS server, which avoids cross-origin limits in the browser. You're running the standalone build, so open the curated sources directly:": "El agregador obtiene fuentes de seguridad y humanitarias a través del servidor AEGIS, lo que evita los límites de origen cruzado del navegador. Está usando la versión autónoma, así que abra las fuentes directamente:",

    /* ---- threat watch ---- */
    "Dashboard": "Panel",
    "Threat Log": "Registro de amenazas",
    "Personnel": "Personal",
    "Regional Risk": "Riesgo regional",
    "GEOINT Map": "Mapa GEOINT",
    "+ Log Threat": "+ Registrar amenaza",
    "+ Add Personnel": "+ Añadir personal",
    "+ Add Region": "+ Añadir región",
    "Severity": "Severidad",
    "Summary": "Resumen",
    "Recommendation": "Recomendación",
    "Source": "Fuente",
    "Location (place)": "Ubicación (lugar)",
    "Country / Area": "País / Zona",
    "Personnel Requiring Attention": "Personal que requiere atención",
    "Fit All": "Ajustar todo",
    "⊹ Fit All": "⊹ Ajustar todo",
    /* display-only record values (selects are skipped, data unchanged) */
    "Active": "Activa",
    "Monitoring": "En seguimiento",
    "Closed": "Cerrada",
    "Accounted For": "Localizado",
    "Check-in Due": "Reporte pendiente",
    "Unreachable": "Ilocalizable",
    "In Transit": "En tránsito",
    "Off-grid OK": "Fuera de red (OK)",
    "Low": "Baja",
    "Guarded": "Cautela",
    "Elevated": "Elevada",
    "High": "Alta",
    "Critical": "Crítica",

    /* ---- analytic workbench ---- */
    "Collection": "Recolección",
    "Reference": "Referencia",
    "Intelligence Log": "Registro de inteligencia",
    "Entity Registry": "Registro de entidades",
    "Link Analysis": "Análisis de vínculos",
    "Competing Hypotheses": "Hipótesis en competencia",
    "Tradecraft Primer": "Manual de oficio",
    "+ Log Reporting": "+ Registrar informe",
    "+ Register Entity": "+ Registrar entidad",
    "+ Add Relationship": "+ Añadir relación",
    "Fit View": "Ajustar vista",
    "⌖ Locate from place": "⌖ Localizar por lugar",
    "⌖ Locate": "⌖ Localizar",
    "Log Reporting": "Registrar informe",
    "Edit Reporting": "Editar informe",
    "Register Entity": "Registrar entidad",
    "Edit Entity": "Editar entidad",
    "Add Relationship": "Añadir relación",
    "Save Reporting": "Guardar informe",
    "Save Entity": "Guardar entidad",
    "Add Link": "Añadir vínculo",
    "Summary / Title": "Resumen / Título",
    "DTG (Date-Time Group)": "DTG (grupo fecha-hora)",
    "Discipline (INT)": "Disciplina (INT)",
    "Source Reliability": "Fiabilidad de la fuente",
    "Info Credibility": "Credibilidad de la información",
    "Raw Reporting": "Informe en bruto",
    "Key Judgment (analyst assessment)": "Juicio clave (evaluación del analista)",
    "Key Judgment": "Juicio clave",
    "Estimative Probability (ICD 203)": "Probabilidad estimativa (ICD 203)",
    "Analytic Confidence": "Confianza analítica",
    "Location (place name)": "Ubicación (nombre del lugar)",
    "Linked Entities (Ctrl/Cmd-click for multiple)": "Entidades vinculadas (Ctrl/Cmd-clic para varias)",
    "Linked Entities": "Entidades vinculadas",
    "Tags (comma-separated)": "Etiquetas (separadas por comas)",
    "Tags": "Etiquetas",
    "Designation / Name": "Designación / Nombre",
    "Aliases / AKA": "Alias / AKA",
    "Aliases": "Alias",
    "Discipline": "Disciplina",
    "Confidence": "Confianza",
    "Entities": "Entidades",
    "Designation": "Designación",
    "Connections": "Conexiones",
    "Reporting": "Informes",
    "Relationships": "Relaciones",
    "Analysis of Competing Hypotheses": "Análisis de Hipótesis en Competencia",
    "Consistency Matrix": "Matriz de consistencia",
    "Add Hypothesis": "Añadir hipótesis",
    "Add Evidence / Argument": "Añadir evidencia / argumento",

    /* ---- trip command ---- */
    "Overview": "Resumen",
    "Itinerary": "Itinerario",
    "Lodging": "Alojamiento",
    "Budget": "Presupuesto",
    "Mission Overview": "Resumen de misión",
    "Day-by-day operations": "Operaciones día a día",
    "Confirmed stays": "Estancias confirmadas",
    "Planned vs. actual": "Planificado vs. real",
    "Geospatial operating picture": "Panorama operativo geoespacial",
    "＋ Trip": "＋ Viaje",
    "＋ Add Event": "＋ Añadir evento",
    "＋ Add Lodging": "＋ Añadir alojamiento",
    "＋ Add Line Item": "＋ Añadir partida",
    "⎙ Print Brief": "⎙ Imprimir informe",
    "⭳ Backup": "⭳ Copia",
    "⭱ Restore": "⭱ Restaurar",
    "New Trip": "Nuevo viaje",
    "Edit Trip": "Editar viaje",
    "Add Event": "Añadir evento",
    "Edit Event": "Editar evento",
    "Add Lodging": "Añadir alojamiento",
    "Edit Lodging": "Editar alojamiento",
    "Add Line Item": "Añadir partida",
    "Edit Line Item": "Editar partida",
    "Trip Name": "Nombre del viaje",
    "Destination": "Destino",
    "Start Date": "Fecha de inicio",
    "End Date": "Fecha de fin",
    "Currency": "Moneda",
    "Property Name": "Nombre del alojamiento",
    "Check-in": "Entrada",
    "Check-out": "Salida",
    "Confirmation #": "N.º de confirmación",
    "Location / Address": "Ubicación / Dirección",

    /* ---- task list ---- */
    "Add a task and press Enter…": "Añada una tarea y pulse Enter…",
    "Clear completed": "Borrar completadas",
    "A clean slate.": "Borrón y cuenta nueva.",
    "Subtask…": "Subtarea…",
    "Saved locally": "Guardado localmente",
    "Saved to database": "Guardado en la base de datos",
    "Nothing yet — add your first task below.": "Nada aún — añada su primera tarea abajo."
  };

  var SKIP = { SCRIPT: 1, STYLE: 1, OPTION: 1, SELECT: 1, TEXTAREA: 1, INPUT: 1, CODE: 1, PRE: 1, NOSCRIPT: 1 };

  function blockedAncestor(node) {
    var el = node.parentNode;
    while (el && el.nodeType === 1) { if (SKIP[el.nodeName]) return true; el = el.parentNode; }
    return false;
  }

  function translateIn(root) {
    var base = (root && (root.nodeType === 1 || root.nodeType === 9)) ? root : document.body;
    if (!base) return;
    var tw = document.createTreeWalker(base, NodeFilter.SHOW_TEXT, null);
    var n;
    while ((n = tw.nextNode())) {
      if (blockedAncestor(n)) continue;
      var raw = n.nodeValue; if (!raw) continue;
      var t = raw.trim(); if (!t) continue;
      var tr = ES[t];
      if (tr && tr !== t) n.nodeValue = raw.replace(t, tr);
    }
    if (base.querySelectorAll) {
      var els = base.querySelectorAll('[placeholder],[title],[aria-label]');
      for (var i = 0; i < els.length; i++) {
        var el = els[i];
        if (SKIP[el.nodeName] && el.nodeName !== 'INPUT' && el.nodeName !== 'TEXTAREA') continue;
        ['placeholder', 'title', 'aria-label'].forEach(function (a) {
          var v = el.getAttribute(a); if (!v) return;
          var k = v.trim(); if (ES[k]) el.setAttribute(a, ES[k]);
        });
      }
    }
  }

  var mo = null;
  function start() {
    document.documentElement.lang = 'es';
    translateIn(document.body);
    mo = new MutationObserver(function (muts) {
      mo.disconnect();   // avoid re-observing our own edits
      for (var i = 0; i < muts.length; i++) {
        var m = muts[i];
        for (var j = 0; j < m.addedNodes.length; j++) {
          var nd = m.addedNodes[j];
          if (nd.nodeType === 1) translateIn(nd);
          else if (nd.nodeType === 3 && !blockedAncestor(nd)) {
            var t = (nd.nodeValue || '').trim();
            if (t && ES[t]) nd.nodeValue = nd.nodeValue.replace(t, ES[t]);
          }
        }
      }
      mo.observe(document.body, { childList: true, subtree: true });
    });
    mo.observe(document.body, { childList: true, subtree: true });
  }

  var api = {
    get: getLang,
    set: function (l) { try { localStorage.setItem(LS_KEY, l === 'es' ? 'es' : 'en'); } catch (e) {} },
    active: function () { return getLang() === 'es'; },
    t: function (s) { return getLang() === 'es' ? (ES[s] || s) : s; }
  };
  if (global.AEGIS) global.AEGIS.i18n = api; else global.AEGIS_I18N = api;

  if (getLang() === 'es') {
    if (document.body) start();
    else document.addEventListener('DOMContentLoaded', start);
  }
})(window);
