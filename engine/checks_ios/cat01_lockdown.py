"""CAT-1 iOS: Live lockdownd queries (no backup required).

Vendored from securityscan-usb/engine/checks_ios/cat01_lockdown.py with Spanish
translations added and the pymobiledevice3 binary resolved lazily through the
app-managed toolchain (engine/ios_toolchain.py). Check IDs preserved.

All checks are read-only on the iPhone side. Failures (device unplugged
mid-scan, lockdownd refusing) become clean Status.ERROR Findings.
"""
from __future__ import annotations

import re

from ..core import Finding, ScanContext, Severity, Status, run_cmd, safe_check
from ..ios_backup import IPhoneInfo
from ..ios_toolchain import pymd3_path

CATEGORY = "CAT-1: iOS Version, Identity & Profiles"
CATEGORY_DE = "CAT-1: iOS-Version, Identität & Profile"
CATEGORY_ES = "CAT-1: Versión de iOS, identidad y perfiles"


def run(ctx: ScanContext, *, phone: IPhoneInfo) -> list[Finding]:
    """Each check is isolated so a crash in one does not kill the rest."""
    out: list[Finding] = []
    out.append(safe_check("IOS-CAT01-001", CATEGORY, _check_ios_version, phone))
    out.append(safe_check("IOS-CAT01-002", CATEGORY, _check_hardware_eol, phone))
    out.append(safe_check("IOS-CAT01-003", CATEGORY, _check_configuration_profiles))
    out.append(safe_check("IOS-CAT01-004", CATEGORY, _check_jailbreak_indicators))
    out.append(safe_check("IOS-CAT01-005", CATEGORY, _check_pairing_records))
    out.append(safe_check("IOS-CAT01-006", CATEGORY, _check_activation_state, phone))
    return out


# iOS major versions still receiving regular security updates from Apple as of
# late 2026. Apple switched to year-based naming in 2026: iOS 18 (2024) was
# followed by iOS 26 (2026), skipping 19-25. Apple typically supports the
# current major plus 1-2 prior majors. Update as Apple rotates support.
IOS_SUPPORTED_MAJORS = {26, 18}

# iPhone product types at or near hardware EOL for our threat model.
EOL_PRODUCT_TYPES = {
    "iPhone10,1": "iPhone 8 (2017) — capped at iOS 16",
    "iPhone10,4": "iPhone 8 (2017) — capped at iOS 16",
    "iPhone10,2": "iPhone 8 Plus (2017) — capped at iOS 16",
    "iPhone10,5": "iPhone 8 Plus (2017) — capped at iOS 16",
    "iPhone8,4":  "iPhone SE 1st gen (2016) — capped at iOS 15",
    "iPhone9,1":  "iPhone 7 (2016) — capped at iOS 15",
    "iPhone9,2":  "iPhone 7 Plus (2016) — capped at iOS 15",
    "iPhone9,3":  "iPhone 7 (2016) — capped at iOS 15",
    "iPhone9,4":  "iPhone 7 Plus (2016) — capped at iOS 15",
}


# --- 1.1 iOS version --------------------------------------------------------

def _check_ios_version(phone: IPhoneInfo) -> Finding:
    version = phone.product_version or "unknown"
    build = phone.build_version or "unknown"
    m = re.match(r"^(\d+)", version)
    major = int(m.group(1)) if m else None

    evidence = f"ProductVersion: {version}\nBuildVersion: {build}\nProductType: {phone.product_type}"

    if major is None:
        return Finding(
            id="IOS-CAT01-001",
            title="iOS version: could not parse",
            description="Verifies the iPhone is on an iOS version still receiving security updates.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.ERROR,
            command="pymobiledevice3 lockdown info",
            evidence=evidence,
            standards=("Apple Platform Security",),
            vector_ids=("O-01",),
            remediation="Settings > General > About > Software Version. Report this to the MobileCheck maintainer.",
            title_de="iOS-Version: nicht parsbar",
            description_de="Prüft, ob das iPhone auf einer iOS-Version läuft, die noch Sicherheitsupdates erhält.",
            remediation_de="Einstellungen > Allgemein > Info > Software-Version. Bitte an die MobileCheck-Maintainer:in melden.",
            category_de=CATEGORY_DE,
            title_es="Versión de iOS: no se pudo determinar",
            description_es="Verifica si el iPhone está en una versión de iOS que aún recibe actualizaciones de seguridad.",
            remediation_es="Ajustes > General > Información > Versión de software. Reporta esto al mantenedor de MobileCheck.",
            category_es=CATEGORY_ES,
        )

    if major in IOS_SUPPORTED_MAJORS:
        return Finding(
            id="IOS-CAT01-001",
            title=f"iOS {version} is on a supported major version",
            description="Apple maintains the current iOS plus typically one or two prior majors with security updates.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command="pymobiledevice3 lockdown info",
            evidence=evidence,
            standards=("Apple Platform Security",),
            vector_ids=("O-01",),
            remediation="No action. Continue to install point releases as Apple publishes them.",
            references=("https://support.apple.com/en-us/HT201222",),
            title_de=f"iOS {version} ist eine unterstützte Hauptversion",
            description_de="Apple unterhält die aktuelle iOS-Version plus üblicherweise ein bis zwei vorherige Hauptversionen mit Sicherheitsupdates.",
            remediation_de="Keine Aktion nötig. Weiter Point-Releases installieren, sobald Apple sie veröffentlicht.",
            category_de=CATEGORY_DE,
            title_es=f"iOS {version} está en una versión principal con soporte",
            description_es="Apple mantiene con actualizaciones de seguridad la versión actual de iOS y normalmente una o dos versiones principales anteriores.",
            remediation_es="Sin acción necesaria. Sigue instalando las versiones menores conforme Apple las publique.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="IOS-CAT01-001",
        title=f"iOS {version} is on an UNSUPPORTED major version",
        description="This iOS major no longer receives security updates from Apple. Known WebKit / iMessage / kernel CVEs remain unpatched. Mercenary spyware exploit chains have historically targeted exactly this gap.",
        category=CATEGORY,
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        command="pymobiledevice3 lockdown info",
        evidence=evidence,
        standards=("Apple Platform Security",),
        vector_ids=("O-01", "M-02", "W-04"),
        remediation="Upgrade iOS to the latest version supported by this hardware (Settings > General > Software Update). If hardware does not support a current iOS major, plan device replacement.",
        interim_mitigation="Until upgrade or replacement: enable Lockdown Mode if available, disable iMessage from unknown senders, do not open links from unknown contacts, set passcode to alphanumeric of 8+ chars, enable USB Restricted Mode, sign out of any non-essential Apple ID services.",
        references=("https://support.apple.com/en-us/HT201222",),
        cve_ids=("CVE-2023-41064", "CVE-2023-41061", "CVE-2024-23222"),
        title_de=f"iOS {version} ist eine NICHT MEHR UNTERSTÜTZTE Hauptversion",
        description_de="Diese iOS-Hauptversion erhält keine Sicherheitsupdates mehr von Apple. Bekannte WebKit-/iMessage-/Kernel-CVEs bleiben ungepatcht. Söldner-Spyware-Exploit-Ketten haben historisch genau diese Lücke ausgenutzt.",
        remediation_de="iOS auf die neueste von dieser Hardware unterstützte Version aktualisieren (Einstellungen > Allgemein > Softwareupdate). Wenn die Hardware keine aktuelle iOS-Version mehr trägt: Gerätewechsel planen.",
        interim_mitigation_de="Bis zum Upgrade oder Austausch: Lockdown Mode aktivieren falls verfügbar, iMessage von unbekannten Absendern deaktivieren, keine Links von unbekannten Kontakten öffnen, alphanumerischen Passcode mit 8+ Zeichen setzen, USB-eingeschränkten Modus aktivieren, von nicht essentiellen Apple-ID-Diensten abmelden.",
        category_de=CATEGORY_DE,
        title_es=f"iOS {version} está en una versión principal SIN SOPORTE",
        description_es="Esta versión principal de iOS ya no recibe actualizaciones de seguridad de Apple. CVE conocidos de WebKit, iMessage y el kernel siguen sin parche. Las cadenas de exploits del spyware mercenario han atacado históricamente exactamente esta brecha.",
        remediation_es="Actualiza iOS a la última versión que admita este hardware (Ajustes > General > Actualización de software). Si el hardware ya no admite una versión actual, planifica el reemplazo del dispositivo.",
        interim_mitigation_es="Hasta actualizar o reemplazar: activa el Modo de Aislamiento si está disponible, desactiva iMessage de remitentes desconocidos, no abras enlaces de contactos desconocidos, usa un código alfanumérico de 8+ caracteres, activa el modo restringido de USB y cierra sesión en servicios no esenciales del Apple ID.",
        category_es=CATEGORY_ES,
    )


# --- 1.2 Hardware end-of-life ---------------------------------------------

def _check_hardware_eol(phone: IPhoneInfo) -> Finding:
    pt = phone.product_type
    if pt in EOL_PRODUCT_TYPES:
        desc = EOL_PRODUCT_TYPES[pt]
        return Finding(
            id="IOS-CAT01-002",
            title=f"Hardware near or past end-of-life: {desc}",
            description="This iPhone model can no longer receive the current iOS version. Apple's mainstream security updates are not available on this hardware. For a high-risk profile (journalists, defenders, sources), the right answer is replacement.",
            category=CATEGORY,
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            command="(pymobiledevice3 lockdown info)",
            evidence=f"ProductType: {pt}\nProductVersion: {phone.product_version}\n-> {desc}",
            standards=("Apple Platform Security",),
            vector_ids=("O-01", "H-01", "M-02"),
            remediation="Plan replacement to a current iPhone model that runs the latest iOS major and supports Lockdown Mode (iPhone XS / 2018 or later — iPhone SE 2nd gen and newer all qualify).",
            interim_mitigation="If immediate replacement is not viable: (1) install the highest iOS this hardware supports and stay current on point releases, (2) sign out of iCloud Photos / iCloud Drive on this device, (3) move sensitive comms to a different device, (4) treat this iPhone as 'lower-trust' — no banking, no work email, no source contacts, (5) keep it powered off when not in active use.",
            references=("https://support.apple.com/en-us/HT201222",),
            title_de=f"Hardware nahe oder über Lebensende-Status: {desc}",
            description_de="Dieses iPhone-Modell kann die aktuelle iOS-Hauptversion nicht mehr erhalten. Apples Mainstream-Sicherheitsupdates stehen für diese Hardware nicht zur Verfügung. Für ein Hochrisiko-Profil (Journalist:innen, Verteidiger:innen, Quellen) ist die richtige Antwort ein Austausch.",
            remediation_de="Austausch planen zu einem aktuellen iPhone-Modell, das die neueste iOS-Hauptversion läuft und Lockdown Mode unterstützt (iPhone XS / 2018 oder neuer — iPhone SE 2. Gen und neuere kommen alle in Frage).",
            interim_mitigation_de="Wenn sofortiger Austausch nicht möglich ist: (1) die höchste unterstützte iOS-Version installieren und Point-Releases aktuell halten, (2) iCloud-Fotos / iCloud-Drive auf diesem Gerät abmelden, (3) sensible Kommunikation auf ein anderes Gerät verlagern, (4) dieses iPhone als 'geringeres Vertrauen' behandeln — kein Online-Banking, keine Arbeits-E-Mail, keine Quellen-Kontakte, (5) bei Nichtnutzung ausgeschaltet halten.",
            category_de=CATEGORY_DE,
            title_es=f"Hardware cerca o más allá del fin de su vida útil: {desc}",
            description_es="Este modelo de iPhone ya no puede recibir la versión actual de iOS. Las actualizaciones de seguridad principales de Apple no están disponibles para este hardware. Para un perfil de alto riesgo (periodistas, defensores, fuentes), la respuesta correcta es el reemplazo.",
            remediation_es="Planifica el reemplazo por un iPhone actual que ejecute la última versión principal de iOS y admita el Modo de Aislamiento (iPhone XS / 2018 o posterior — el iPhone SE 2.ª gen y posteriores califican).",
            interim_mitigation_es="Si el reemplazo inmediato no es viable: (1) instala el iOS más alto que admita este hardware y mantén las versiones menores al día, (2) cierra sesión de Fotos de iCloud / iCloud Drive en este dispositivo, (3) mueve las comunicaciones sensibles a otro dispositivo, (4) trata este iPhone como de 'menor confianza' — sin banca, sin correo de trabajo, sin contactos de fuentes, (5) mantenlo apagado cuando no lo uses.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="IOS-CAT01-002",
        title=f"Hardware ({pt}) is current",
        description="iPhone model is recent enough to receive current iOS security updates and Lockdown Mode.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.PASS,
        command="(pymobiledevice3 lockdown info)",
        evidence=f"ProductType: {pt}\nProductVersion: {phone.product_version}",
        standards=("Apple Platform Security",),
        vector_ids=("H-01",),
        remediation="No action.",
        title_de=f"Hardware ({pt}) ist aktuell",
        description_de="iPhone-Modell ist neu genug, um aktuelle iOS-Sicherheitsupdates und Lockdown Mode zu erhalten.",
        remediation_de="Keine Aktion nötig.",
        category_de=CATEGORY_DE,
        title_es=f"El hardware ({pt}) está vigente",
        description_es="El modelo de iPhone es lo bastante reciente para recibir las actualizaciones de seguridad actuales de iOS y el Modo de Aislamiento.",
        remediation_es="Sin acción necesaria.",
        category_es=CATEGORY_ES,
    )


# --- 1.3 Configuration profiles --------------------------------------------

def _check_configuration_profiles() -> Finding:
    pymd3 = pymd3_path()
    if not pymd3:
        return _ios_deps_missing_finding("IOS-CAT01-003",
                                         "Configuration profiles", "M-02", "N-05", "C-02")

    r = run_cmd([pymd3, "--no-color", "profile", "list"], timeout=15)
    if not r.ok:
        return Finding(
            id="IOS-CAT01-003",
            title="Could not list configuration profiles",
            description="Configuration Profiles can silently install root CAs, force VPN, enroll the device into MDM, or restrict features. Their presence on a personal iPhone is suspect unless you knowingly installed each one.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.stdout or r.exception)[:400],
            standards=("Apple Platform Security",),
            vector_ids=("N-05", "C-02", "M-02"),
            remediation="On the iPhone: Settings > General > VPN & Device Management — review every entry manually.",
            title_de="Konfigurationsprofile konnten nicht aufgelistet werden",
            description_de="Konfigurationsprofile können stillschweigend Root-CAs installieren, VPN erzwingen, das Gerät in MDM einschreiben oder Funktionen einschränken. Ihre Anwesenheit auf einem privaten iPhone ist verdächtig, es sei denn du hast jedes wissentlich installiert.",
            remediation_de="Auf dem iPhone: Einstellungen > Allgemein > VPN & Geräteverwaltung — jeden Eintrag manuell prüfen.",
            category_de=CATEGORY_DE,
            title_es="No se pudieron listar los perfiles de configuración",
            description_es="Los perfiles de configuración pueden instalar CA raíz en silencio, forzar VPN, inscribir el dispositivo en MDM o restringir funciones. Su presencia en un iPhone personal es sospechosa salvo que hayas instalado cada uno a sabiendas.",
            remediation_es="En el iPhone: Ajustes > General > VPN y gestión de dispositivos — revisa cada entrada manualmente.",
            category_es=CATEGORY_ES,
        )

    txt = r.stdout.strip()
    profiles = _parse_profile_list(txt)

    if not profiles:
        return Finding(
            id="IOS-CAT01-003",
            title="No configuration profiles installed",
            description="No Configuration Profiles found. Expected default for a personal device.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=txt[:400] or "(empty list)",
            standards=("Apple Platform Security",),
            vector_ids=("N-05", "C-02", "M-02"),
            remediation="No action.",
            title_de="Keine Konfigurationsprofile installiert",
            description_de="Keine Konfigurationsprofile gefunden. Erwarteter Standard auf einem privaten Gerät.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="Sin perfiles de configuración instalados",
            description_es="No se encontraron perfiles de configuración. Es lo esperado en un dispositivo personal.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="IOS-CAT01-003",
        title=f"{len(profiles)} configuration profile(s) installed — review each",
        description="Configuration Profiles grant powerful trust to whoever issued them. Each entry must be intentional and from a known issuer (employer MDM, university wifi, Apple Beta). Anything else needs investigation — this is the #1 vector for 'legal spyware'.",
        category=CATEGORY,
        severity=Severity.CRITICAL,
        status=Status.WARN,
        command=r.cmd,
        evidence=txt[:2000],
        standards=("Apple Platform Security",),
        vector_ids=("N-05", "C-02", "M-02"),
        remediation="On iPhone: Settings > General > VPN & Device Management > tap each profile > review what it does > if you did not knowingly install it, tap 'Remove Profile'. Legitimate examples: employer MDM (Jamf, Intune, etc.), university wifi, Apple Beta Software Program. ANY other issuer needs investigation.",
        interim_mitigation="If unsure but cannot remove now: screenshot the profile list and consult someone you trust before next sensitive use of the device.",
        title_de=f"{len(profiles)} Konfigurationsprofil(e) installiert — jedes prüfen",
        description_de="Konfigurationsprofile gewähren dem Aussteller weitreichendes Vertrauen. Jeder Eintrag muss bewusst sein und von einem bekannten Aussteller stammen (Arbeitgeber-MDM, Uni-WLAN, Apple Beta). Alles andere braucht eine Untersuchung — das ist der #1-Vektor für 'legale Spyware'.",
        remediation_de="Auf dem iPhone: Einstellungen > Allgemein > VPN & Geräteverwaltung > jedes Profil antippen > prüfen, was es tut > wenn du es nicht wissentlich installiert hast, 'Profil entfernen' antippen. Legitime Beispiele: Arbeitgeber-MDM (Jamf, Intune usw.), Uni-WLAN, Apple Beta Software Program. JEDER andere Aussteller braucht eine Untersuchung.",
        interim_mitigation_de="Wenn unsicher, aber gerade nicht entfernbar: Screenshot der Profilliste machen und eine vertrauenswürdige Person konsultieren, bevor du das Gerät erneut für sensible Aufgaben nutzt.",
        category_de=CATEGORY_DE,
        title_es=f"{len(profiles)} perfil(es) de configuración instalados — revisa cada uno",
        description_es="Los perfiles de configuración otorgan una confianza enorme a quien los emitió. Cada entrada debe ser intencional y de un emisor conocido (MDM del empleador, Wi-Fi universitario, Apple Beta). Cualquier otra cosa requiere investigación — este es el vector #1 del 'spyware legal'.",
        remediation_es="En el iPhone: Ajustes > General > VPN y gestión de dispositivos > toca cada perfil > revisa qué hace > si no lo instalaste a sabiendas, toca 'Eliminar perfil'. Ejemplos legítimos: MDM del empleador (Jamf, Intune, etc.), Wi-Fi universitario, Apple Beta Software Program. CUALQUIER otro emisor requiere investigación.",
        interim_mitigation_es="Si tienes dudas pero no puedes eliminarlo ahora: toma captura de la lista de perfiles y consulta a alguien de confianza antes del próximo uso sensible del dispositivo.",
        category_es=CATEGORY_ES,
    )


def _parse_profile_list(txt: str) -> list[str]:
    """Best-effort: count rows that look like profile entries."""
    profiles = []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith(("─", "│", "╭", "╰", "┌", "└", "├", "Identifier", "PayloadIdentifier")):
            continue
        # Heuristic: lines containing a dot (likely a reverse-DNS payload identifier)
        if "." in line and len(line) > 5:
            profiles.append(line[:200])
    return profiles


# --- 1.4 Jailbreak indicators ----------------------------------------------

def _check_jailbreak_indicators() -> Finding:
    pymd3 = pymd3_path()
    if not pymd3:
        return _ios_deps_missing_finding("IOS-CAT01-004", "Jailbreak indicators", "M-02")

    # Presence of Cydia / Sileo / Zebra among installed apps is a hard signal.
    # NOTE: pymobiledevice3 3.x uses --type User (not --user).
    r = run_cmd([pymd3, "--no-color", "apps", "list", "--type", "User"], timeout=20)
    if not r.ok:
        return Finding(
            id="IOS-CAT01-004",
            title="Could not enumerate apps for jailbreak check",
            description="Looks for known jailbreak package managers (Cydia, Sileo, Zebra) among installed apps.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:300],
            standards=("Apple Platform Security",),
            vector_ids=("M-02",),
            remediation="On iPhone: Spotlight search 'Cydia', 'Sileo', 'Zebra'. None should appear.",
            title_de="Apps für Jailbreak-Prüfung nicht abrufbar",
            description_de="Sucht nach bekannten Jailbreak-Paketmanagern (Cydia, Sileo, Zebra) unter den installierten Apps.",
            remediation_de="Auf dem iPhone: Spotlight 'Cydia', 'Sileo', 'Zebra' suchen. Keine sollte erscheinen.",
            category_de=CATEGORY_DE,
            title_es="No se pudieron enumerar las apps para la verificación de jailbreak",
            description_es="Busca gestores de paquetes de jailbreak conocidos (Cydia, Sileo, Zebra) entre las apps instaladas.",
            remediation_es="En el iPhone: busca en Spotlight 'Cydia', 'Sileo', 'Zebra'. No debería aparecer ninguno.",
            category_es=CATEGORY_ES,
        )

    txt = r.stdout.lower()
    indicators = []
    for needle in ("cydia", "sileo", "zebra", "checkra1n", "unc0ver", "taurine"):
        if needle in txt:
            indicators.append(needle)

    if not indicators:
        return Finding(
            id="IOS-CAT01-004",
            title="No jailbreak package managers detected",
            description="None of the well-known jailbreak package managers are installed.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence="Checked: cydia, sileo, zebra, checkra1n, unc0ver, taurine.",
            standards=("Apple Platform Security",),
            vector_ids=("M-02",),
            remediation="No action.",
            title_de="Keine Jailbreak-Paketmanager erkannt",
            description_de="Keiner der bekannten Jailbreak-Paketmanager ist installiert.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="No se detectaron gestores de paquetes de jailbreak",
            description_es="Ninguno de los gestores de paquetes de jailbreak conocidos está instalado.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="IOS-CAT01-004",
        title=f"Possible jailbreak indicators: {', '.join(indicators)}",
        description="One or more known jailbreak components were detected. If the user did not intentionally jailbreak this device, treat as compromised.",
        category=CATEGORY,
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        command=r.cmd,
        evidence=f"Indicators matched: {indicators}",
        standards=("Apple Platform Security",),
        vector_ids=("M-02",),
        remediation="If jailbreak was not intentional: assume the device is compromised. Do NOT remove the jailbreak first — preserve evidence. Take photos of the screen, contact Access Now Digital Security Helpline. If intentional: be aware that jailbreak removes most of Apple's security guarantees and is incompatible with high-risk usage.",
        references=("https://www.accessnow.org/help/",),
        title_de=f"Mögliche Jailbreak-Indikatoren: {', '.join(indicators)}",
        description_de="Eine oder mehrere bekannte Jailbreak-Komponenten wurden erkannt. Wenn die Nutzer:in das Gerät nicht absichtlich gejailbreakt hat, als kompromittiert behandeln.",
        remediation_de="Wenn der Jailbreak nicht beabsichtigt war: Gerät als kompromittiert annehmen. Den Jailbreak NICHT zuerst entfernen — Beweise erhalten. Bildschirm fotografieren, Access Now Digital Security Helpline kontaktieren. Wenn beabsichtigt: bewusst sein, dass Jailbreak die meisten Sicherheitsgarantien Apples entfernt und mit Hochrisiko-Nutzung unvereinbar ist.",
        category_de=CATEGORY_DE,
        title_es=f"Posibles indicadores de jailbreak: {', '.join(indicators)}",
        description_es="Se detectaron uno o más componentes conocidos de jailbreak. Si no hiciste jailbreak a este dispositivo intencionalmente, trátalo como comprometido.",
        remediation_es="Si el jailbreak no fue intencional: asume que el dispositivo está comprometido. NO elimines el jailbreak primero — preserva la evidencia. Fotografía la pantalla y contacta la Línea de Ayuda de Seguridad Digital de Access Now. Si fue intencional: ten presente que el jailbreak elimina la mayoría de las garantías de seguridad de Apple y es incompatible con un uso de alto riesgo.",
        category_es=CATEGORY_ES,
    )


# --- 1.5 Pairing records ---------------------------------------------------

def _check_pairing_records() -> Finding:
    """Pairing records are kept on the iPhone for every Mac/PC it has trusted.
    Many old pairings = many trusted hosts = larger attack surface."""
    pymd3 = pymd3_path()
    if not pymd3:
        return _ios_deps_missing_finding("IOS-CAT01-005", "Pairing records", "F-01")

    # No stable public CLI for the device-side count — surface a manual hint.
    return Finding(
        id="IOS-CAT01-005",
        title="Pairing records: manual review on the iPhone",
        description="Every computer the iPhone has 'Trusted' has a pairing record stored. Many records = larger attack surface (a compromised previously-trusted computer can pull a backup without the user re-trusting).",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.SKIP,
        command="(no stable CLI for this — manual)",
        evidence="To clear all trusts: Settings > General > Transfer or Reset iPhone > Reset > Reset Location & Privacy. This forces every future computer connection to re-prompt 'Trust This Computer?'.",
        standards=("Apple Platform Security",),
        vector_ids=("F-01", "F-02"),
        remediation="If you have not done this in a while, run 'Reset Location & Privacy' on the iPhone to clear all trust records. You'll re-trust this computer on the next scan.",
        title_de="Pairing-Einträge: manuelle Prüfung am iPhone",
        description_de="Jeder Computer, dem das iPhone 'Vertraut' hat, hat einen Pairing-Eintrag. Viele Einträge = größere Angriffsfläche (ein kompromittierter, vorher vertrauter Computer kann ohne erneutes Vertrauen ein Backup ziehen).",
        remediation_de="Wenn du das länger nicht getan hast: 'Standort & Datenschutz zurücksetzen' am iPhone ausführen, um alle Trust-Einträge zu löschen. Beim nächsten Scan vertraust du diesem Computer erneut.",
        category_de=CATEGORY_DE,
        title_es="Registros de emparejamiento: revisión manual en el iPhone",
        description_es="Cada computadora en la que el iPhone 'Confió' guarda un registro de emparejamiento. Muchos registros = mayor superficie de ataque (una computadora antes confiable y ahora comprometida puede extraer un respaldo sin que vuelvas a confiar).",
        remediation_es="Si no lo has hecho en un tiempo, ejecuta 'Restablecer localización y privacidad' en el iPhone para borrar todos los registros de confianza. Volverás a confiar en esta computadora en el próximo análisis.",
        category_es=CATEGORY_ES,
    )


# --- 1.6 Activation state --------------------------------------------------

def _check_activation_state(phone: IPhoneInfo) -> Finding:
    """Activation Lock = Find My iPhone enabled = if stolen, useless to thief."""
    pymd3 = pymd3_path()
    if not pymd3:
        return _ios_deps_missing_finding("IOS-CAT01-006", "Activation state", "F-03")

    r = run_cmd([pymd3, "--no-color", "activation", "state"], timeout=10)
    if not r.ok:
        return Finding(
            id="IOS-CAT01-006",
            title="Could not query activation state",
            description="Verifies Activation Lock (anti-theft) is enabled.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:300],
            standards=("Apple Platform Security",),
            vector_ids=("F-03",),
            remediation="On iPhone: Settings > [your name] > Find My > Find My iPhone > must be ON.",
            title_de="Aktivierungsstatus nicht abrufbar",
            description_de="Prüft, ob Aktivierungssperre (Diebstahlschutz) aktiviert ist.",
            remediation_de="Auf dem iPhone: Einstellungen > [dein Name] > Wo ist? > iPhone suchen > muss EIN sein.",
            category_de=CATEGORY_DE,
            title_es="No se pudo consultar el estado de activación",
            description_es="Verifica que el Bloqueo de Activación (antirrobo) esté habilitado.",
            remediation_es="En el iPhone: Ajustes > [tu nombre] > Buscar > Buscar mi iPhone > debe estar ACTIVADO.",
            category_es=CATEGORY_ES,
        )

    txt = r.stdout.lower()
    activated = "activated" in txt
    return Finding(
        id="IOS-CAT01-006",
        title=("Device is activated" if activated else "Activation state inconclusive"),
        description="Activation status reported by lockdownd. A 'WildcardActivated' or similar value is normal for a working iPhone.",
        category=CATEGORY,
        severity=Severity.LOW,
        status=Status.PASS if activated else Status.WARN,
        command=r.cmd,
        evidence=r.stdout.strip()[:400],
        standards=("Apple Platform Security",),
        vector_ids=("F-03",),
        remediation="No action if activated. Otherwise verify Find My is on (Settings > [name] > Find My).",
        title_de=("Gerät ist aktiviert" if activated else "Aktivierungsstatus nicht eindeutig"),
        description_de="Vom lockdownd gemeldeter Aktivierungsstatus. Ein 'WildcardActivated' oder ähnlich ist normal für ein funktionierendes iPhone.",
        remediation_de="Keine Aktion nötig falls aktiviert. Sonst sicherstellen, dass 'Wo ist?' eingeschaltet ist (Einstellungen > [Name] > Wo ist?).",
        category_de=CATEGORY_DE,
        title_es=("El dispositivo está activado" if activated else "Estado de activación no concluyente"),
        description_es="Estado de activación reportado por lockdownd. Un valor 'WildcardActivated' o similar es normal en un iPhone funcional.",
        remediation_es="Sin acción si está activado. De lo contrario verifica que Buscar esté activado (Ajustes > [nombre] > Buscar).",
        category_es=CATEGORY_ES,
    )


# --- helper ----------------------------------------------------------------

def _ios_deps_missing_finding(check_id: str, what: str, *vector_ids: str) -> Finding:
    return Finding(
        id=check_id,
        title=f"{what}: iOS toolchain not installed",
        description="iOS scans need the app-managed toolchain (pymobiledevice3 + MVT). Run the one-time iOS setup from the scan screen.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.ERROR,
        command="(missing dependency)",
        evidence="pymobiledevice3 was not found in the app-managed venv, PATH, or ~/Library/Python/*/bin",
        standards=(),
        vector_ids=vector_ids,
        remediation="In MobileCheck: open the scan screen with the iPhone connected and run 'Set up iOS scanning'.",
        title_de=f"{what}: iOS-Werkzeuge nicht installiert",
        description_de="iOS-Scans brauchen die app-verwaltete Werkzeugkette (pymobiledevice3 + MVT). Führe die einmalige iOS-Einrichtung im Scan-Bildschirm aus.",
        remediation_de="In MobileCheck: Scan-Bildschirm mit verbundenem iPhone öffnen und 'iOS-Scan einrichten' ausführen.",
        category_de=CATEGORY_DE,
        title_es=f"{what}: herramientas de iOS no instaladas",
        description_es="Los análisis de iOS necesitan las herramientas gestionadas por la app (pymobiledevice3 + MVT). Ejecuta la configuración única de iOS desde la pantalla de análisis.",
        remediation_es="En MobileCheck: abre la pantalla de análisis con el iPhone conectado y ejecuta 'Configurar análisis de iOS'.",
        category_es=CATEGORY_ES,
    )
