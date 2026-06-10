"""CAT-2 iOS: MVT IoC matches + derived checks from the encrypted backup.

Vendored from securityscan-usb/engine/checks_ios/cat02_backup.py with Spanish
translations added. Check IDs preserved (IOS-CAT02-*).

This module runs AFTER ios_backup.make_encrypted_backup() has produced a backup.
It receives:
  - `mvt_summary`: parsed output of `mvt-ios check-backup` (per-module JSONs)
  - `backup_dir`: path to the on-disk backup (for our own derived checks)

We surface MVT detections as one Finding per matched IoC family, plus our own
checks for Lockdown Mode / ADP / trust store.
"""
from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any

from ..core import Finding, ScanContext, Severity, Status, safe_check
from ..ios_backup import IPhoneInfo

CATEGORY = "CAT-2: Mercenary Spyware & Privacy Posture"
CATEGORY_DE = "CAT-2: Söldner-Spyware & Datenschutz-Status"
CATEGORY_ES = "CAT-2: Spyware mercenario y postura de privacidad"


def run(ctx: ScanContext, *, phone: IPhoneInfo, mvt_summary: dict[str, Any],
        backup_dir: Path | None) -> list[Finding]:
    out: list[Finding] = []
    # MVT detections come first because they're the highest-severity findings.
    # This helper returns a LIST, so it can't go through safe_check (which yields
    # one Finding). Guard it explicitly: a backup-parsing crash here must never
    # drop the derived checks below — those are where Lockdown/ADP/CA live.
    try:
        out.extend(_mvt_detections_to_findings(mvt_summary))
    except Exception:
        # Re-run through safe_check to capture the traceback as a CRASH Finding.
        out.append(safe_check("IOS-CAT02-001", CATEGORY,
                              _mvt_detections_to_findings, mvt_summary))
    # Then our own derived checks if we have backup access.
    if backup_dir is not None:
        out.append(safe_check("IOS-CAT02-901", CATEGORY, _check_lockdown_mode, backup_dir))
        out.append(safe_check("IOS-CAT02-902", CATEGORY, _check_advanced_data_protection, backup_dir))
        out.append(safe_check("IOS-CAT02-903", CATEGORY, _check_custom_ca_roots, backup_dir))
    out.append(safe_check("IOS-CAT02-999", CATEGORY, _check_modules_run_summary, mvt_summary))
    return out


# --- 2.1+ MVT detections ----------------------------------------------------

# IoC group names we know to flag at maximum severity. MVT module names are
# stable across versions; new ones added by Citizen Lab/Amnesty land under
# `<name>_detected.json`.
KNOWN_HIGH_SIGNAL_MODULES = {
    "shutdown_log",
    "datausage",
    "net_usage",
    "interaction_c",
    "safari_history",
    "safari_browser_state",
    "tcc",
    "webkit_session_resource_log",
    "configuration_profiles",
}


def _mvt_detections_to_findings(summary: dict[str, Any]) -> list[Finding]:
    detected = summary.get("detected", {}) or {}

    if not detected:
        # MVT ran cleanly with no IoC matches — that's the desired outcome.
        return [Finding(
            id="IOS-CAT02-001",
            title="MVT IoC scan: no matches against current indicator feeds",
            description="The Mobile Verification Toolkit ran a full backup analysis against the loaded IoC indicators (Citizen Lab, Amnesty Tech) and found no matches. This is the desired outcome.",
            category=CATEGORY,
            severity=Severity.CRITICAL,
            status=Status.PASS,
            command="mvt-ios check-backup --iocs <feeds>",
            evidence=f"Modules with results: {len(summary.get('modules_run', []))}",
            standards=("Citizen Lab IoCs", "Amnesty MVT"),
            vector_ids=("M-02",),
            remediation="No action. Refresh the threat indicators from the app periodically and re-scan — new IoCs are published regularly.",
            references=(
                "https://github.com/mvt-project/mvt-indicators",
                "https://citizenlab.ca/",
            ),
            title_de="MVT-IoC-Scan: keine Treffer gegen aktuelle Indikator-Feeds",
            description_de="Das Mobile Verification Toolkit hat eine vollständige Backup-Analyse gegen die geladenen IoC-Indikatoren (Citizen Lab, Amnesty Tech) durchgeführt und keine Treffer gefunden. Das ist das gewünschte Ergebnis.",
            remediation_de="Keine Aktion nötig. Aktualisiere die Bedrohungsindikatoren regelmäßig in der App und scanne erneut — neue IoCs werden regelmäßig veröffentlicht.",
            category_de=CATEGORY_DE,
            title_es="Análisis MVT de IoC: sin coincidencias con los indicadores actuales",
            description_es="El Mobile Verification Toolkit analizó el respaldo completo contra los indicadores IoC cargados (Citizen Lab, Amnesty Tech) y no encontró coincidencias. Este es el resultado deseado.",
            remediation_es="Sin acción necesaria. Actualiza los indicadores de amenazas desde la app periódicamente y vuelve a analizar — se publican IoC nuevos con regularidad.",
            category_es=CATEGORY_ES,
        )]

    findings: list[Finding] = []
    for idx, (module_name, hits) in enumerate(detected.items(), start=2):
        sev = Severity.CRITICAL if module_name in KNOWN_HIGH_SIGNAL_MODULES else Severity.HIGH
        findings.append(Finding(
            id=f"IOS-CAT02-{idx:03d}",
            title=f"MVT detection: {module_name} matched {len(hits)} indicator(s)",
            description=f"Mobile Verification Toolkit's `{module_name}` module matched one or more public IoCs. This is a serious signal — IoCs are added to the public feeds only after Citizen Lab or Amnesty Tech have confirmed the artifact in known compromise cases. False positives are possible but should always be investigated by an expert.",
            category=CATEGORY,
            severity=sev,
            status=Status.FAIL,
            command=f"mvt-ios check-backup (module: {module_name})",
            evidence=_render_mvt_hits(hits),
            standards=("Citizen Lab IoCs", "Amnesty MVT"),
            vector_ids=("M-02",),
            remediation=("DO NOT modify or wipe the device. Disconnect from sensitive accounts. "
                         "Contact Access Now Digital Security Helpline (https://www.accessnow.org/help/) "
                         "or Citizen Lab for forensic-grade analysis. Preserve the device powered on."),
            interim_mitigation="Take photos of this report. Do not factory reset. Do not install/uninstall apps. Do not log in to additional accounts from this device.",
            references=(
                "https://www.accessnow.org/help/",
                "https://citizenlab.ca/",
                "https://github.com/mvt-project/mvt-indicators",
            ),
            title_de=f"MVT-Erkennung: {module_name} hat {len(hits)} Indikator(en) gematcht",
            description_de=f"Das `{module_name}`-Modul des Mobile Verification Toolkits hat einen oder mehrere öffentliche IoCs gematcht. Das ist ein ernstes Signal — IoCs werden öffentlichen Feeds erst hinzugefügt, nachdem Citizen Lab oder Amnesty Tech das Artefakt in bekannten Kompromittierungsfällen bestätigt haben. Falsch-Positive sind möglich, sollten aber immer von einer Expert:in untersucht werden.",
            remediation_de=("Das Gerät NICHT modifizieren oder zurücksetzen. Von sensiblen Konten abmelden. "
                            "Access Now Digital Security Helpline (https://www.accessnow.org/help/) "
                            "oder Citizen Lab für forensische Analyse kontaktieren. Gerät eingeschaltet erhalten."),
            interim_mitigation_de="Diesen Bericht fotografieren. Kein Werksreset. Keine Apps installieren/deinstallieren. Von diesem Gerät keine zusätzlichen Konten anmelden.",
            category_de=CATEGORY_DE,
            title_es=f"Detección MVT: {module_name} coincidió con {len(hits)} indicador(es)",
            description_es=f"El módulo `{module_name}` del Mobile Verification Toolkit coincidió con uno o más IoC públicos. Es una señal seria — los IoC se agregan a los feeds públicos solo después de que Citizen Lab o Amnesty Tech confirmaron el artefacto en casos conocidos de compromiso. Los falsos positivos son posibles pero siempre deben ser investigados por una persona experta.",
            remediation_es=("NO modifiques ni restablezcas el dispositivo. Desconéctate de cuentas sensibles. "
                            "Contacta la Línea de Ayuda de Seguridad Digital de Access Now (https://www.accessnow.org/help/) "
                            "o Citizen Lab para un análisis forense. Mantén el dispositivo encendido."),
            interim_mitigation_es="Fotografía este informe. No restablezcas de fábrica. No instales/desinstales apps. No inicies sesión en cuentas adicionales desde este dispositivo.",
            category_es=CATEGORY_ES,
        ))
    return findings


def _render_mvt_hits(hits: list[Any]) -> str:
    """Render up to N hits as a readable evidence string."""
    if not isinstance(hits, list):
        return str(hits)[:1000]
    lines = []
    for h in hits[:10]:
        if isinstance(h, dict):
            # Common MVT fields
            parts = []
            for k in ("matched_indicator", "domain", "url", "process", "name", "timestamp", "isodate"):
                if k in h:
                    parts.append(f"{k}={h[k]}")
            lines.append("  " + (" | ".join(parts) if parts else str(h)[:200]))
        else:
            lines.append("  " + str(h)[:200])
    if len(hits) > 10:
        lines.append(f"  ... +{len(hits) - 10} more")
    return "\n".join(lines)


# --- 2.x Lockdown Mode (derived from backup) -------------------------------

def _check_lockdown_mode(backup_dir: Path) -> Finding:
    """Lockdown Mode is in com.apple.security.lockdownmode preferences."""
    candidates = list(backup_dir.rglob("*com.apple.security.lockdownmode*"))
    if not candidates:
        return Finding(
            id="IOS-CAT02-901",
            title="Lockdown Mode: state not found in backup (manual check)",
            description="We could not locate the Lockdown Mode preferences file in the backup. This usually means it has never been enabled (the file is created on first toggle). For high-risk users, Lockdown Mode is the single most impactful one-tap hardening Apple offers.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.SKIP,
            command="(backup parser)",
            evidence=f"No matching plist under {backup_dir.name}",
            standards=("Apple Platform Security",),
            vector_ids=("M-02", "E-03", "W-04"),
            remediation="On iPhone: Settings > Privacy & Security > Lockdown Mode > Turn On Lockdown Mode > Turn On & Restart. (Requires iOS 16+.)",
            references=("https://support.apple.com/en-us/105120",),
            title_de="Lockdown Mode: Status nicht im Backup gefunden (manuelle Prüfung)",
            description_de="Die Lockdown-Mode-Einstellungsdatei konnte im Backup nicht gefunden werden. Das bedeutet meistens, dass er nie aktiviert wurde (die Datei wird beim ersten Umschalten erstellt). Für Hochrisiko-Personen ist Lockdown Mode die wirkungsvollste Ein-Klick-Härtung, die Apple bietet.",
            remediation_de="Auf dem iPhone: Einstellungen > Datenschutz & Sicherheit > Lockdown Mode > Aktivieren > Aktivieren & Neu starten. (Erfordert iOS 16+.)",
            category_de=CATEGORY_DE,
            title_es="Modo de Aislamiento: estado no encontrado en el respaldo (verificación manual)",
            description_es="No pudimos localizar el archivo de preferencias del Modo de Aislamiento en el respaldo. Normalmente significa que nunca se activó (el archivo se crea al activarlo por primera vez). Para personas de alto riesgo, el Modo de Aislamiento es el endurecimiento de un toque más efectivo que ofrece Apple.",
            remediation_es="En el iPhone: Ajustes > Privacidad y seguridad > Modo de Aislamiento > Activar Modo de Aislamiento > Activar y reiniciar. (Requiere iOS 16+.)",
            category_es=CATEGORY_ES,
        )

    # If we found it, try to read it
    for p in candidates:
        try:
            with open(p, "rb") as f:
                data = plistlib.load(f)
            if data.get("LDMGlobalEnabled") or data.get("Enabled") or data.get("LockdownMode"):
                return Finding(
                    id="IOS-CAT02-901",
                    title="Lockdown Mode appears to be ENABLED",
                    description="Lockdown Mode preferences indicate the global toggle is on.",
                    category=CATEGORY,
                    severity=Severity.HIGH,
                    status=Status.PASS,
                    command="(backup parser)",
                    evidence=f"{p.name}\nKeys: {list(data.keys())[:10]}",
                    standards=("Apple Platform Security",),
                    vector_ids=("M-02",),
                    remediation="No action. Confirm on device: Settings > Privacy & Security > Lockdown Mode.",
                    title_de="Lockdown Mode scheint AKTIVIERT",
                    description_de="Die Lockdown-Mode-Einstellungen zeigen, dass der globale Schalter eingeschaltet ist.",
                    remediation_de="Keine Aktion nötig. Auf dem Gerät bestätigen: Einstellungen > Datenschutz & Sicherheit > Lockdown Mode.",
                    category_de=CATEGORY_DE,
                    title_es="El Modo de Aislamiento parece estar ACTIVADO",
                    description_es="Las preferencias del Modo de Aislamiento indican que el interruptor global está encendido.",
                    remediation_es="Sin acción necesaria. Confirma en el dispositivo: Ajustes > Privacidad y seguridad > Modo de Aislamiento.",
                    category_es=CATEGORY_ES,
                )
        except Exception:
            continue

    return Finding(
        id="IOS-CAT02-901",
        title="Lockdown Mode preferences exist but state unclear",
        description="Found the preferences file but could not confidently determine its on/off state. Verify on device.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.WARN,
        command="(backup parser)",
        evidence=f"Files: {[p.name for p in candidates[:5]]}",
        standards=("Apple Platform Security",),
        vector_ids=("M-02",),
        remediation="On iPhone: Settings > Privacy & Security > Lockdown Mode — verify visually.",
        title_de="Lockdown-Mode-Einstellungen vorhanden, Status unklar",
        description_de="Einstellungsdatei gefunden, aber Ein-/Aus-Status nicht eindeutig. Am Gerät prüfen.",
        remediation_de="Auf dem iPhone: Einstellungen > Datenschutz & Sicherheit > Lockdown Mode — visuell prüfen.",
        category_de=CATEGORY_DE,
        title_es="Existen preferencias del Modo de Aislamiento pero el estado no es claro",
        description_es="Se encontró el archivo de preferencias pero no se pudo determinar con confianza si está activado o no. Verifica en el dispositivo.",
        remediation_es="En el iPhone: Ajustes > Privacidad y seguridad > Modo de Aislamiento — verifica visualmente.",
        category_es=CATEGORY_ES,
    )


# --- 2.y Advanced Data Protection ------------------------------------------

def _check_advanced_data_protection(backup_dir: Path) -> Finding:
    """ADP enables E2EE for most iCloud data classes. State lives in CloudKit
    keychain entries — not trivially extractable. We give a manual hint."""
    return Finding(
        id="IOS-CAT02-902",
        title="Advanced Data Protection: manual check on device",
        description="ADP applies end-to-end encryption to iCloud Backup, Notes, Photos, Reminders, Safari Bookmarks and more. Without ADP, Apple can decrypt this data and so can anyone with legal/coercive access to Apple. For high-risk users, ADP is essential.",
        category=CATEGORY,
        severity=Severity.HIGH,
        status=Status.SKIP,
        command="(no reliable backup-side detection)",
        evidence="ADP state is gated by iCloud Keychain and not surfaced in regular backup files.",
        standards=("Apple Platform Security",),
        vector_ids=("C-01", "C-05"),
        remediation="On iPhone: Settings > [your name] > iCloud > Advanced Data Protection > turn ON. You will be required to set up a recovery contact OR a recovery key — write the key down and store it physically (NOT in iCloud / NOT on the same device).",
        interim_mitigation="If you can't enable ADP yet (e.g. you have devices on iOS <16.2 still on your account): upgrade or remove those devices first. Do not skip ADP for a high-risk profile.",
        references=("https://support.apple.com/en-us/108756",),
        title_de="Advanced Data Protection: manuelle Prüfung am Gerät",
        description_de="ADP wendet Ende-zu-Ende-Verschlüsselung auf iCloud-Backup, Notizen, Fotos, Erinnerungen, Safari-Lesezeichen und mehr an. Ohne ADP kann Apple diese Daten entschlüsseln, und damit auch jede Person mit legalem/erzwungenem Zugriff auf Apple. Für Hochrisiko-Personen ist ADP essentiell.",
        remediation_de="Auf dem iPhone: Einstellungen > [dein Name] > iCloud > Advanced Data Protection > einschalten. Du musst eine Wiederherstellungs-Kontaktperson ODER einen Wiederherstellungsschlüssel einrichten — den Schlüssel aufschreiben und physisch lagern (NICHT in iCloud / NICHT auf demselben Gerät).",
        interim_mitigation_de="Wenn ADP gerade nicht aktivierbar ist (z. B. du hast noch Geräte mit iOS <16.2 in deinem Account): erst diese Geräte aktualisieren oder entfernen. Bei Hochrisiko-Profil ADP nicht überspringen.",
        category_de=CATEGORY_DE,
        title_es="Protección de Datos Avanzada: verificación manual en el dispositivo",
        description_es="La ADP aplica cifrado de extremo a extremo al respaldo de iCloud, Notas, Fotos, Recordatorios, favoritos de Safari y más. Sin ADP, Apple puede descifrar esos datos, igual que cualquiera con acceso legal o coercitivo a Apple. Para personas de alto riesgo, la ADP es esencial.",
        remediation_es="En el iPhone: Ajustes > [tu nombre] > iCloud > Protección de Datos Avanzada > ACTIVAR. Tendrás que configurar un contacto de recuperación O una clave de recuperación — anota la clave y guárdala físicamente (NO en iCloud / NO en el mismo dispositivo).",
        interim_mitigation_es="Si aún no puedes activar la ADP (p. ej. tienes dispositivos con iOS <16.2 en tu cuenta): primero actualiza o elimina esos dispositivos. No omitas la ADP en un perfil de alto riesgo.",
        category_es=CATEGORY_ES,
    )


# --- 2.z Custom CA roots ---------------------------------------------------

def _check_custom_ca_roots(backup_dir: Path) -> Finding:
    """Custom trusted CAs let MITM TLS interception happen silently. Look for
    TrustStore.sqlite3 or similar in the backup."""
    candidates = list(backup_dir.rglob("TrustStore.sqlite3")) + \
                 list(backup_dir.rglob("*ManagedConfiguration*"))
    if not candidates:
        return Finding(
            id="IOS-CAT02-903",
            title="No custom trust store artifacts found in backup",
            description="No TrustStore.sqlite3 or ManagedConfiguration files surfaced. Default Apple trust applies; no operator-installed CAs detected via this signal.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command="(backup parser)",
            evidence="No matching files in backup.",
            standards=("Apple Platform Security",),
            vector_ids=("N-05",),
            remediation="No action. Verify on device: Settings > General > About > Certificate Trust Settings — list should be empty for a personal device.",
            title_de="Keine benutzerdefinierten Trust-Store-Artefakte im Backup gefunden",
            description_de="Keine TrustStore.sqlite3 oder ManagedConfiguration-Dateien aufgetaucht. Standard-Apple-Trust gilt; keine fremdinstallierten CAs über dieses Signal erkannt.",
            remediation_de="Keine Aktion nötig. Am Gerät bestätigen: Einstellungen > Allgemein > Info > Zertifikatsvertrauenseinstellungen — Liste sollte für ein privates Gerät leer sein.",
            category_de=CATEGORY_DE,
            title_es="Sin artefactos de almacén de confianza personalizados en el respaldo",
            description_es="No aparecieron archivos TrustStore.sqlite3 ni ManagedConfiguration. Aplica la confianza estándar de Apple; no se detectaron CA instaladas por terceros mediante esta señal.",
            remediation_es="Sin acción necesaria. Verifica en el dispositivo: Ajustes > General > Información > Configuración de confianza de certificados — la lista debería estar vacía en un dispositivo personal.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="IOS-CAT02-903",
        title=f"Trust store artifacts present in backup ({len(candidates)} file(s)) — manual review",
        description="Files related to managed certificates / trust store were found. This can be normal (e.g. employer device) or a sign of TLS interception infrastructure. Each requires identification.",
        category=CATEGORY,
        severity=Severity.HIGH,
        status=Status.WARN,
        command="(backup parser)",
        evidence="\n".join(p.name for p in candidates[:10]),
        standards=("Apple Platform Security",),
        vector_ids=("N-05", "C-02"),
        remediation="On iPhone: Settings > General > About > Certificate Trust Settings > review every entry. Settings > General > VPN & Device Management > review every profile that installed a CA. If unrecognized, remove.",
        title_de=f"Trust-Store-Artefakte im Backup vorhanden ({len(candidates)} Datei(en)) — manuelle Prüfung",
        description_de="Dateien zu verwalteten Zertifikaten / Trust-Store wurden gefunden. Das kann normal sein (z. B. Arbeitgeber-Gerät) oder ein Zeichen für TLS-Interception-Infrastruktur. Jede erfordert Identifikation.",
        remediation_de="Auf dem iPhone: Einstellungen > Allgemein > Info > Zertifikatsvertrauenseinstellungen > jeden Eintrag prüfen. Einstellungen > Allgemein > VPN & Geräteverwaltung > jedes Profil prüfen, das eine CA installiert hat. Wenn unbekannt, entfernen.",
        category_de=CATEGORY_DE,
        title_es=f"Hay artefactos del almacén de confianza en el respaldo ({len(candidates)} archivo(s)) — revisión manual",
        description_es="Se encontraron archivos relacionados con certificados gestionados / almacén de confianza. Puede ser normal (p. ej. dispositivo del empleador) o señal de infraestructura de interceptación TLS. Cada uno requiere identificación.",
        remediation_es="En el iPhone: Ajustes > General > Información > Configuración de confianza de certificados > revisa cada entrada. Ajustes > General > VPN y gestión de dispositivos > revisa cada perfil que haya instalado una CA. Si no lo reconoces, elimínalo.",
        category_es=CATEGORY_ES,
    )


# --- summary footer --------------------------------------------------------

def _check_modules_run_summary(summary: dict[str, Any]) -> Finding:
    """Informational: which MVT modules ran. Helpful audit trail."""
    modules = summary.get("modules_run", [])
    errors = summary.get("errors", [])
    return Finding(
        id="IOS-CAT02-999",
        title=f"MVT analysis completed: {len(modules)} module(s) executed",
        description="Reference list of MVT modules that produced output. Errors during MVT (rare) are listed in evidence.",
        category=CATEGORY,
        severity=Severity.INFO,
        status=Status.PASS if not errors else Status.WARN,
        command="mvt-ios check-backup",
        evidence=("Modules: " + ", ".join(modules[:30])
                  + (f"\nErrors: {len(errors)}\n" + "\n".join(errors[:5]) if errors else "")),
        standards=("Amnesty MVT",),
        vector_ids=("M-02",),
        remediation="Reference only. No action.",
        title_de=f"MVT-Analyse abgeschlossen: {len(modules)} Modul(e) ausgeführt",
        description_de="Referenz-Liste der MVT-Module, die Output produziert haben. Fehler während MVT (selten) sind im Nachweis gelistet.",
        remediation_de="Nur als Referenz. Keine Aktion.",
        category_de=CATEGORY_DE,
        title_es=f"Análisis MVT completado: {len(modules)} módulo(s) ejecutados",
        description_es="Lista de referencia de los módulos MVT que produjeron resultados. Los errores durante MVT (raros) se listan en la evidencia.",
        remediation_es="Solo referencia. Sin acción necesaria.",
        category_es=CATEGORY_ES,
    )
