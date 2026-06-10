/* MobileCheck landing — language toggle. Static, no network, no trackers. */
(function () {
  'use strict';

  const STRINGS = {
    es: {
      eyebrow: 'C-LAB · Herramienta · autoevaluación del teléfono',
      role: 'Solo lectura · local · código abierto',
      hero_title: 'Revisa la seguridad de tu teléfono.',
      hero_lead: 'Descarga MobileCheck a tu computadora, conecta tu teléfono con un cable USB y ejecuta un análisis de solo lectura: indicadores de spyware, stalkerware y configuraciones riesgosas. En iPhone usa MVT de Amnesty contra los indicadores de Citizen Lab y Amnesty. Todo corre en tu computadora; no se envía nada a menos que tú lo decidas.',
      cta_mac: 'Descargar para macOS',
      cta_win: 'Descargar para Windows',
      hero_note: 'La app corre en tu Mac o PC; analiza Android e iPhone por USB · gratis y de código abierto · ',
      all_downloads: 'todas las descargas y sumas de verificación',
      f1_t: 'Solo lectura',
      f1_d: 'Observa e informa. No instala nada en el teléfono ni cambia su configuración.',
      f2_t: 'Local y privada',
      f2_d: 'El análisis corre en tu computadora. Sin cuenta, sin subida, sin telemetría.',
      f3_t: 'Informe en lenguaje claro',
      f3_d: 'Una puntuación de seguridad y lo primero que debes corregir, cada cosa con pasos claros.',
      f4_t: 'Sigue tu progreso',
      f4_d: 'Un historial local cifrado muestra si la seguridad de tu teléfono mejora con el tiempo.',
      f5_t: 'Informes en EN / ES / DE',
      f5_d: 'Descarga un informe PDF imprimible en inglés, español o alemán.',
      f6_t: 'Compartir cifrado, opcional',
      f6_d: 'Ayuda a la red de investigación de C-LAB con un archivo cifrado, solo si tú quieres. Los hallazgos de spyware nunca van en una exportación de rutina.',
      prot_h: 'Qué detecta',
      prot_1: 'Indicadores de spyware mercenario en iPhone (Pegasus, Predator) con MVT de Amnesty, y stalkerware comercial en Android.',
      prot_2: 'Servicios de accesibilidad, lectores de notificaciones, apps administradoras, proxies, VPN forzadas, certificados y perfiles riesgosos.',
      prot_3: 'Parches de seguridad atrasados, arranque verificado, jailbreak / root y una lista clara y priorizada de correcciones.',
      no_h: 'Qué no es',
      no_1: 'No es una herramienta forense. Es un triaje rápido; para evidencia judicial se necesita una adquisición completa.',
      no_2: 'Un resultado limpio NO es prueba de seguridad: el spyware sin clics avanzado puede no dejar rastro visible por USB.',
      no_3: 'No es un recolector de datos. El respaldo temporal del iPhone se elimina al terminar; nunca se suben tus mensajes ni fotos.',
      verify_note: 'Verifica cada descarga con su SHA-256 antes de abrirla. Las sumas se publican con cada versión.',
      foot_net: 'Parte de la red ARGUS'
    },
    en: {
      eyebrow: 'C-LAB · Tool · phone self-assessment',
      role: 'Read-only · local · open source',
      hero_title: "Check your phone's security.",
      hero_lead: 'Download MobileCheck to your computer, plug your phone in with a USB cable, and run a read-only scan: spyware indicators, stalkerware, risky settings. On iPhone it uses Amnesty\'s MVT against Citizen Lab and Amnesty indicators. Everything runs on your computer; nothing is sent unless you choose to.',
      cta_mac: 'Download for macOS',
      cta_win: 'Download for Windows',
      hero_note: 'The app runs on your Mac or PC; it scans Android and iPhone over USB · free & open source · ',
      all_downloads: 'all downloads & checksums',
      f1_t: 'Read-only',
      f1_d: 'It observes and reports. It installs nothing on the phone and changes no settings.',
      f2_t: 'Local & private',
      f2_d: 'The scan runs on your computer. No account, no upload, no telemetry.',
      f3_t: 'Plain-language report',
      f3_d: 'A health score and the top things to fix first, each with clear steps.',
      f4_t: 'Track your progress',
      f4_d: "An encrypted local history shows whether your phone's security is improving over time.",
      f5_t: 'Reports in EN / ES / DE',
      f5_d: 'Download a printable PDF report in English, Spanish, or German.',
      f6_t: 'Optional encrypted sharing',
      f6_d: 'Help the C-LAB research network with an encrypted file, only if you choose. Spyware findings are never in a routine export.',
      prot_h: 'What it finds',
      prot_1: "Mercenary-spyware indicators on iPhone (Pegasus, Predator) via Amnesty's MVT, and commercial stalkerware on Android.",
      prot_2: 'Accessibility services, notification listeners, device-admin apps, proxies, forced VPNs, risky certificates and profiles.',
      prot_3: 'Stale security patches, verified boot, jailbreak / root, and a clear, prioritized list of fixes.',
      no_h: 'What it is not',
      no_1: 'Not a forensic tool. It is a fast triage; court-grade evidence needs a full acquisition.',
      no_2: 'A clean result is NOT proof of safety. Advanced zero-click spyware may leave no USB-visible trace.',
      no_3: 'Not a data collector. The temporary iPhone backup is deleted when done; your messages and photos are never uploaded.',
      verify_note: 'Verify every download against its SHA-256 before opening. Checksums are published with each release.',
      foot_net: 'Part of the ARGUS Defense Network'
    }
  };

  function applyLang(lang) {
    document.documentElement.lang = lang;
    const t = STRINGS[lang];
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (t[key] !== undefined) el.textContent = t[key];
    });
    document.querySelectorAll('.lang-switch button').forEach(b => {
      b.classList.toggle('active', b.dataset.lang === lang);
    });
  }

  document.querySelectorAll('.lang-switch button').forEach(b => {
    b.addEventListener('click', () => applyLang(b.dataset.lang));
  });

  // Default to the browser's preferred language if it's English, else Spanish.
  const pref = (navigator.language || 'es').toLowerCase().startsWith('en') ? 'en' : 'es';
  applyLang(pref);
})();
