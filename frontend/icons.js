/* =============================================================
   ARGUS · icon registry, Iconsax-style outline icons
   24x24 viewBox · stroke 1.5 · round caps/joins · currentColor
   Usage: <i data-ico="shield"></i>  -> hydrated to inline SVG
   ============================================================= */
(function () {
  const P = {
    shield:
      '<path d="M12 22s8-3.5 8-9.5V5.6L12 2.5 4 5.6v6.9C4 18.5 12 22 12 22Z"/><path d="M9.2 12.2 11 14l3.8-4"/>',
    radar:
      '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 19.5 7"/><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/>',
    globe:
      '<circle cx="12" cy="12" r="9"/><path d="M3.2 9h17.6M3.2 15h17.6"/><path d="M12 3c2.6 2.4 4 5.6 4 9s-1.4 6.6-4 9c-2.6-2.4-4-5.6-4-9s1.4-6.6 4-9Z"/>',
    document:
      '<path d="M14 2.5H7.5A2.5 2.5 0 0 0 5 5v14a2.5 2.5 0 0 0 2.5 2.5h9A2.5 2.5 0 0 0 19 19V7.5L14 2.5Z"/><path d="M13.8 2.7V7a1 1 0 0 0 1 1h4.3"/><path d="M8.5 13h7M8.5 16.5h4.5"/>',
    book:
      '<path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v15.5H6.5A2.5 2.5 0 0 0 4 21V5.5Z"/><path d="M4 18.5A2.5 2.5 0 0 1 6.5 16H20"/><path d="M8 7.5h7"/>',
    cpu:
      '<rect x="6.5" y="6.5" width="11" height="11" rx="2.2"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/><path d="M9.5 3v3M14.5 3v3M9.5 18v3M14.5 18v3M3 9.5h3M3 14.5h3M18 9.5h3M18 14.5h3"/>',
    activity:
      '<path d="M3 12h4l2.5-7 5 14L17 12h4"/>',
    chart:
      '<path d="M4 4v15a1 1 0 0 0 1 1h15"/><path d="M7.5 15l3.5-4 3 2.5L20 7"/>',
    lock:
      '<rect x="4.5" y="10.5" width="15" height="10.5" rx="2.4"/><path d="M7.5 10.5V7.5a4.5 4.5 0 0 1 9 0v3"/><circle cx="12" cy="15.5" r="1.4" fill="currentColor" stroke="none"/>',
    search:
      '<circle cx="11" cy="11" r="7"/><path d="M16.2 16.2 21 21"/>',
    terminal:
      '<rect x="2.8" y="4.5" width="18.4" height="15" rx="2.4"/><path d="M7 9.5l3 2.5-3 2.5M12.5 15h4.5"/>',
    flash:
      '<path d="M13.5 2.5 5 13.2h6l-.5 8.3L19 10.8h-6l.5-8.3Z"/>',
    people:
      '<circle cx="9" cy="8" r="3.2"/><path d="M3.5 20a5.5 5.5 0 0 1 11 0"/><path d="M16 5.2a3.2 3.2 0 0 1 0 5.8M17.5 20a5.5 5.5 0 0 0-3-4.9"/>',
    verify:
      '<path d="M12 2.5 5 5.6v6.9C5 18.5 12 22 12 22s7-3.5 7-9.5V5.6L12 2.5Z"/><path d="M9 12l2 2 4-4"/>',
    broadcast:
      '<circle cx="12" cy="12" r="2"/><path d="M7.8 7.8a6 6 0 0 0 0 8.4M16.2 16.2a6 6 0 0 0 0-8.4"/><path d="M5 5a9.5 9.5 0 0 0 0 14M19 19a9.5 9.5 0 0 0 0-14"/>',
    flask:
      '<path d="M9.5 3h5M10 3v6.2L5.4 17a2.4 2.4 0 0 0 2.1 3.6h9a2.4 2.4 0 0 0 2.1-3.6L14 9.2V3"/><path d="M7.5 14.5h9"/>',
    arrowUpRight:
      '<path d="M7 17 17 7M9 7h8v8"/>',
    pulse:
      '<circle cx="12" cy="12" r="9"/><path d="M7 12h2l1.5-3.5L13 16l1.5-4H17"/>',
    crosshair:
      '<circle cx="12" cy="12" r="8"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/>',
    eye:
      '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/>',
    layers:
      '<path d="M12 3 3 7.5 12 12l9-4.5L12 3Z"/><path d="M3.5 12 12 16.3 20.5 12M3.5 16.5 12 20.8l8.5-4.3"/>',
    mail:
      '<rect x="3" y="5.5" width="18" height="13" rx="2.4"/><path d="m4 7 8 6 8-6"/>',
    grid:
      '<rect x="3.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.6"/>',
    chat:
      '<path d="M21 11.5a8 8 0 0 1-11.6 7.1L4 20.5l1.9-5.4A8 8 0 1 1 21 11.5Z"/><path d="M8.5 11.5h.01M12 11.5h.01M15.5 11.5h.01"/>',
    download:
      '<path d="M12 3v12M7.5 10.5 12 15l4.5-4.5"/><path d="M4.5 19.5h15"/>',
    apple:
      '<path d="M16.3 12.3c0-2.3 1.9-3.4 2-3.5-1.1-1.6-2.8-1.8-3.4-1.8-1.4-.1-2.8.9-3.5.9s-1.8-.8-3-.8c-1.5 0-3 .9-3.8 2.3-1.6 2.8-.4 7 1.2 9.3.8 1.1 1.7 2.4 2.9 2.3 1.2 0 1.6-.7 3-.7s1.8.7 3 .7 2-1.1 2.8-2.2c.9-1.3 1.2-2.5 1.3-2.6-.1 0-2.5-1-2.5-3.8Z"/><path d="M14 5.2c.6-.8 1-1.8.9-2.9-.9 0-2 .6-2.6 1.4-.6.7-1.1 1.7-1 2.7 1 .1 2-.5 2.7-1.2Z"/>',
    github:
      '<path d="M9 19c-4 1.2-4-1.8-5.5-2.2M14.5 21v-3.1c0-.9.1-1.3-.5-1.8 2.5-.3 4.8-1.2 4.8-5.3a4 4 0 0 0-1.1-2.8 3.7 3.7 0 0 0-.1-2.8s-.9-.3-3 .9a10.4 10.4 0 0 0-5.4 0C7 2.6 6.1 2.9 6.1 2.9a3.7 3.7 0 0 0-.1 2.8A4 4 0 0 0 4.9 8.5c0 4.1 2.3 5 4.8 5.3-.5.5-.5 1-.5 1.9V21"/>',
    key:
      '<circle cx="7.5" cy="14.5" r="3.5"/><path d="M10 12 20 2M16 6l2.5 2.5M13.5 8.5 16 11"/>',
    copy:
      '<rect x="8.5" y="8.5" width="11" height="11" rx="2"/><path d="M5.5 15.5A2 2 0 0 1 4.5 14V6a2 2 0 0 1 2-2h7a2 2 0 0 1 1.5.6"/>',
    timer:
      '<circle cx="12" cy="13.5" r="7.5"/><path d="M12 13.5V9M9.5 2.5h5"/><path d="m17.5 6 1.3-1.3"/>',
    fingerprint:
      '<path d="M5.5 12a6.5 6.5 0 0 1 11-4.7M18.5 12c0 3.5-.5 6-.5 6M5.5 12v3.5M9 12a3 3 0 0 1 6 0c0 4 .5 5.5.5 5.5M12 12v2c0 3 .8 4.7.8 4.7M8 16c0 2 .8 3.5.8 3.5"/>',
    compare:
      '<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M6 8.5V14a3 3 0 0 0 3 3h6M18 15.5V10a3 3 0 0 0-3-3H9"/><path d="m11.5 4.5 1.5 1.5-1.5 1.5M12.5 19.5 11 18l1.5-1.5"/>',
    refresh:
      '<path d="M4 12a8 8 0 0 1 13.7-5.6L20 8.5M20 4v4.5h-4.5"/><path d="M20 12a8 8 0 0 1-13.7 5.6L4 15.5M4 20v-4.5h4.5"/>',
    bolt:
      '<rect x="4.5" y="3.5" width="15" height="17" rx="2.4"/><path d="M8.5 8h7M8.5 12h7M8.5 16h4"/>',
    cloudOff:
      '<path d="M3 3l18 18"/><path d="M7 16.5A4 4 0 0 1 6.5 8.6M9 6.2A6 6 0 0 1 18 11a3.5 3.5 0 0 1 1.3 6.6"/>',
  };

  function svg(name) {
    const body = P[name] || P.crosshair;
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
  }

  function hydrate(root) {
    (root || document).querySelectorAll('[data-ico]').forEach((el) => {
      if (el.dataset.icoDone) return;
      el.innerHTML = svg(el.getAttribute('data-ico'));
      el.dataset.icoDone = '1';
    });
  }

  window.ArgusIcons = { svg, hydrate, names: Object.keys(P) };
  if (document.readyState !== 'loading') hydrate();
  else document.addEventListener('DOMContentLoaded', () => hydrate());
})();
