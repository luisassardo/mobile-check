"""CAT-1: OS & Device Integrity checks for Android (over ADB, read-only).

Ported from android-triage.command (DEV-001..DEV-005), same severity logic.
All queries are getprop / pm / ls reads; nothing on the phone is modified.
"""
from __future__ import annotations

import time

from ..core import Finding, ScanContext, Severity, Status, safe_check
from .. import adb

CATEGORY = "CAT-1: OS & Device Integrity"
CATEGORY_DE = "CAT-1: System & Geräteintegrität"
CATEGORY_ES = "CAT-1: Sistema e integridad del dispositivo"


def run(ctx: ScanContext) -> list[Finding]:
    serial = getattr(ctx, "target_serial", "") or ""
    out: list[Finding] = []
    out.append(safe_check("ANDROID-CAT01-001", CATEGORY, _check_device_info, serial))
    out.append(safe_check("ANDROID-CAT01-002", CATEGORY, _check_patch_age, serial))
    out.append(safe_check("ANDROID-CAT01-003", CATEGORY, _check_verified_boot, serial))
    out.append(safe_check("ANDROID-CAT01-004", CATEGORY, _check_build_type, serial))
    out.append(safe_check("ANDROID-CAT01-005", CATEGORY, _check_root_indicators, serial))
    return out


# --- 1.1 Device identity (informational) -------------------------------------

def _check_device_info(serial: str) -> Finding:
    brand = adb.getprop("ro.product.manufacturer", serial)
    model = adb.getprop("ro.product.model", serial)
    version = adb.getprop("ro.build.version.release", serial)
    sdk = adb.getprop("ro.build.version.sdk", serial)
    fingerprint = adb.getprop("ro.build.fingerprint", serial)
    return Finding(
        id="ANDROID-CAT01-001",
        title=f"Device: {brand} {model} (Android {version} / SDK {sdk})",
        description="Records which device and Android version were scanned, so the rest of the report can be read in context.",
        category=CATEGORY,
        severity=Severity.INFO,
        status=Status.PASS,
        command="adb shell getprop",
        evidence=f"manufacturer={brand}\nmodel={model}\nandroid={version} sdk={sdk}\nfingerprint={fingerprint}",
        vector_ids=("O-01",),
        standards=("OWASP MASVS",),
        remediation="No action. This entry documents the scanned device.",
        title_de=f"Gerät: {brand} {model} (Android {version} / SDK {sdk})",
        description_de="Hält fest, welches Gerät und welche Android-Version geprüft wurden, damit der restliche Bericht im Kontext lesbar ist.",
        remediation_de="Keine Aktion nötig. Dieser Eintrag dokumentiert das geprüfte Gerät.",
        category_de=CATEGORY_DE,
        title_es=f"Dispositivo: {brand} {model} (Android {version} / SDK {sdk})",
        description_es="Registra qué dispositivo y qué versión de Android se analizaron, para leer el resto del informe en contexto.",
        remediation_es="Sin acción necesaria. Esta entrada documenta el dispositivo analizado.",
        category_es=CATEGORY_ES,
    )


# --- 1.2 Security patch staleness --------------------------------------------

def _check_patch_age(serial: str) -> Finding:
    patch = adb.getprop("ro.build.version.security_patch", serial)
    base = dict(
        id="ANDROID-CAT01-002",
        description="Checks how old the installed Android security patch level is. Old patch levels leave the device exposed to publicly known, already-fixed exploits (n-days).",
        category=CATEGORY,
        command="adb shell getprop ro.build.version.security_patch",
        vector_ids=("O-01", "O-02"),
        standards=("OWASP MASVS", "CIS"),
        description_de="Prüft, wie alt der installierte Android-Sicherheitspatch ist. Alte Patch-Stände lassen das Gerät gegen öffentlich bekannte, bereits behobene Exploits (N-Days) ungeschützt.",
        category_de=CATEGORY_DE,
        description_es="Verifica qué tan antiguo es el nivel de parche de seguridad instalado. Niveles viejos dejan el dispositivo expuesto a exploits públicos ya corregidos (n-days).",
        category_es=CATEGORY_ES,
    )
    if not patch:
        return Finding(
            title="Could not read the security patch level",
            severity=Severity.MEDIUM, status=Status.WARN,
            evidence="ro.build.version.security_patch is empty",
            remediation="Check Settings > Security > Security update on the phone and install any pending update.",
            title_de="Sicherheitspatch-Stand konnte nicht gelesen werden",
            remediation_de="Prüfe auf dem Telefon Einstellungen > Sicherheit > Sicherheitsupdate und installiere ausstehende Updates.",
            title_es="No se pudo leer el nivel de parche de seguridad",
            remediation_es="Revisa en el teléfono Ajustes > Seguridad > Actualización de seguridad e instala cualquier actualización pendiente.",
            **base,
        )
    days = _days_since(patch)
    if days is None:
        return Finding(
            title=f"Security patch level has an unexpected format: {patch}",
            severity=Severity.LOW, status=Status.WARN,
            evidence=f"security_patch={patch}",
            remediation="Verify the patch date manually in Settings > About phone.",
            title_de=f"Sicherheitspatch-Stand hat ein unerwartetes Format: {patch}",
            remediation_de="Prüfe das Patch-Datum manuell unter Einstellungen > Über das Telefon.",
            title_es=f"El nivel de parche tiene un formato inesperado: {patch}",
            remediation_es="Verifica la fecha del parche manualmente en Ajustes > Información del teléfono.",
            **base,
        )
    if days > 180:
        return Finding(
            title=f"Security patch is {days} days old ({patch})",
            severity=Severity.HIGH, status=Status.FAIL,
            evidence=f"security_patch={patch} ({days} days)",
            remediation="Update Android now (Settings > System > System update). More than 180 days unpatched means many public exploits apply to this device.",
            interim_mitigation="If the device no longer receives updates, plan replacement. Until then: avoid opening links and attachments from unknown senders, keep apps updated via Play Store, and consider moving sensitive accounts to another device.",
            title_de=f"Sicherheitspatch ist {days} Tage alt ({patch})",
            remediation_de="Aktualisiere Android jetzt (Einstellungen > System > Systemupdate). Über 180 Tage ohne Patches bedeutet, dass viele öffentliche Exploits auf dieses Gerät anwendbar sind.",
            interim_mitigation_de="Wenn das Gerät keine Updates mehr erhält, plane einen Gerätewechsel. Bis dahin: keine Links/Anhänge unbekannter Absender öffnen, Apps über den Play Store aktuell halten und sensible Konten möglichst auf ein anderes Gerät verlegen.",
            title_es=f"El parche de seguridad tiene {days} días ({patch})",
            remediation_es="Actualiza Android ahora (Ajustes > Sistema > Actualización del sistema). Más de 180 días sin parches significa que muchos exploits públicos aplican a este dispositivo.",
            interim_mitigation_es="Si el dispositivo ya no recibe actualizaciones, planifica reemplazarlo. Mientras tanto: no abras enlaces ni adjuntos de remitentes desconocidos, mantén las apps actualizadas vía Play Store y considera mover cuentas sensibles a otro dispositivo.",
            **base,
        )
    if days > 90:
        return Finding(
            title=f"Security patch is {days} days old ({patch})",
            severity=Severity.MEDIUM, status=Status.FAIL,
            evidence=f"security_patch={patch} ({days} days)",
            remediation="Apply pending system updates (Settings > System > System update).",
            title_de=f"Sicherheitspatch ist {days} Tage alt ({patch})",
            remediation_de="Installiere ausstehende Systemupdates (Einstellungen > System > Systemupdate).",
            title_es=f"El parche de seguridad tiene {days} días ({patch})",
            remediation_es="Instala las actualizaciones pendientes (Ajustes > Sistema > Actualización del sistema).",
            **base,
        )
    return Finding(
        title=f"Security patch is reasonably current ({patch}, {days} days)",
        severity=Severity.INFO, status=Status.PASS,
        evidence=f"security_patch={patch} ({days} days)",
        remediation="No action. Keep installing updates as they arrive.",
        title_de=f"Sicherheitspatch ist hinreichend aktuell ({patch}, {days} Tage)",
        remediation_de="Keine Aktion nötig. Installiere Updates weiterhin, sobald sie erscheinen.",
        title_es=f"El parche de seguridad está razonablemente al día ({patch}, {days} días)",
        remediation_es="Sin acción necesaria. Sigue instalando actualizaciones cuando lleguen.",
        **base,
    )


def _days_since(date_str: str) -> int | None:
    try:
        t = time.mktime(time.strptime(date_str.strip(), "%Y-%m-%d"))
        return int((time.time() - t) / 86400)
    except (ValueError, OverflowError):
        return None


# --- 1.3 Verified boot / bootloader -------------------------------------------

def _check_verified_boot(serial: str) -> Finding:
    vbstate = adb.getprop("ro.boot.verifiedbootstate", serial).lower()
    locked = adb.getprop("ro.boot.flash.locked", serial)
    base = dict(
        id="ANDROID-CAT01-003",
        description="Verified Boot guarantees the operating system has not been modified. A green/locked state means the bootloader is locked and the OS is intact; yellow or orange means it was unlocked or altered, which allows persistent implants.",
        category=CATEGORY,
        command="adb shell getprop ro.boot.verifiedbootstate",
        vector_ids=("O-03", "H-01"),
        standards=("OWASP MASVS", "Android Platform Security"),
        description_de="Verified Boot garantiert, dass das Betriebssystem nicht verändert wurde. Grün/gesperrt heißt: Bootloader gesperrt, System intakt. Gelb oder Orange heißt: entsperrt oder verändert, was persistente Implantate ermöglicht.",
        category_de=CATEGORY_DE,
        description_es="Verified Boot garantiza que el sistema operativo no fue modificado. Verde/bloqueado significa bootloader bloqueado y sistema intacto; amarillo o naranja significa desbloqueado o alterado, lo que permite implantes persistentes.",
        category_es=CATEGORY_ES,
    )
    evidence = f"verifiedbootstate={vbstate or '(empty)'} flash.locked={locked or '(empty)'}"
    if vbstate == "green":
        return Finding(
            title="Verified boot: green (locked, OS unmodified)",
            severity=Severity.INFO, status=Status.PASS, evidence=evidence,
            remediation="No action.",
            title_de="Verified Boot: grün (gesperrt, System unverändert)",
            remediation_de="Keine Aktion nötig.",
            title_es="Verified boot: verde (bloqueado, sistema sin modificar)",
            remediation_es="Sin acción necesaria.",
            **base,
        )
    if vbstate in ("yellow", "orange"):
        return Finding(
            title=f"Verified boot: {vbstate} (bootloader unlocked / OS modified)",
            severity=Severity.HIGH, status=Status.FAIL, evidence=evidence,
            remediation="An unlocked bootloader allows persistent implants that survive app removal. If you did not unlock it yourself, treat the device as untrusted: back up your data, factory reset, and re-lock the bootloader.",
            interim_mitigation="Until you can reset: do not use this device for sensitive communications or accounts.",
            title_de=f"Verified Boot: {vbstate} (Bootloader entsperrt / System verändert)",
            remediation_de="Ein entsperrter Bootloader ermöglicht persistente Implantate, die das Entfernen von Apps überleben. Wenn du ihn nicht selbst entsperrt hast, behandle das Gerät als nicht vertrauenswürdig: Daten sichern, auf Werkseinstellungen zurücksetzen, Bootloader wieder sperren.",
            interim_mitigation_de="Bis zum Zurücksetzen: Nutze dieses Gerät nicht für sensible Kommunikation oder Konten.",
            title_es=f"Verified boot: {vbstate} (bootloader desbloqueado / sistema modificado)",
            remediation_es="Un bootloader desbloqueado permite implantes persistentes que sobreviven a la eliminación de apps. Si no lo desbloqueaste tú, trata el dispositivo como no confiable: respalda tus datos, restablece de fábrica y vuelve a bloquear el bootloader.",
            interim_mitigation_es="Hasta poder restablecerlo: no uses este dispositivo para comunicaciones o cuentas sensibles.",
            **base,
        )
    return Finding(
        title="Verified boot state could not be determined",
        severity=Severity.LOW, status=Status.WARN, evidence=evidence,
        remediation="Some manufacturers do not expose this property. Verify device integrity manually: Settings > Security, and confirm you never unlocked the bootloader.",
        title_de="Verified-Boot-Status konnte nicht ermittelt werden",
        remediation_de="Manche Hersteller geben diese Eigenschaft nicht preis. Prüfe die Geräteintegrität manuell: Einstellungen > Sicherheit, und bestätige, dass der Bootloader nie entsperrt wurde.",
        title_es="No se pudo determinar el estado de verified boot",
        remediation_es="Algunos fabricantes no exponen esta propiedad. Verifica la integridad manualmente: Ajustes > Seguridad, y confirma que nunca desbloqueaste el bootloader.",
        **base,
    )


# --- 1.4 Build type ------------------------------------------------------------

def _check_build_type(serial: str) -> Finding:
    buildtype = adb.getprop("ro.build.type", serial)
    base = dict(
        id="ANDROID-CAT01-004",
        description="Retail phones run 'user' builds. 'userdebug' or 'eng' builds have relaxed security (debuggable, root-capable) and are unexpected on a normal phone.",
        category=CATEGORY,
        command="adb shell getprop ro.build.type",
        vector_ids=("O-03",),
        standards=("Android Platform Security",),
        description_de="Handelsübliche Telefone laufen mit 'user'-Builds. 'userdebug'- oder 'eng'-Builds haben gelockerte Sicherheit (debugbar, root-fähig) und sind auf einem normalen Telefon unerwartet.",
        category_de=CATEGORY_DE,
        description_es="Los teléfonos de venta normal usan builds 'user'. Los builds 'userdebug' o 'eng' tienen seguridad relajada (depurables, con capacidad de root) y son inesperados en un teléfono normal.",
        category_es=CATEGORY_ES,
    )
    if buildtype and buildtype != "user":
        return Finding(
            title=f"Non-production build type: {buildtype}",
            severity=Severity.HIGH, status=Status.FAIL,
            evidence=f"ro.build.type={buildtype}",
            remediation="A userdebug/eng build on a retail phone is a red flag. Investigate where the device came from; if its provenance is unclear, do not use it for sensitive work.",
            title_de=f"Kein Produktions-Build: {buildtype}",
            remediation_de="Ein userdebug/eng-Build auf einem handelsüblichen Telefon ist ein Alarmsignal. Kläre die Herkunft des Geräts; ist sie unklar, nutze es nicht für sensible Arbeit.",
            title_es=f"Build no de producción: {buildtype}",
            remediation_es="Un build userdebug/eng en un teléfono comercial es una señal de alerta. Investiga la procedencia del dispositivo; si no es clara, no lo uses para trabajo sensible.",
            **base,
        )
    return Finding(
        title="Production build type (user)",
        severity=Severity.INFO, status=Status.PASS,
        evidence=f"ro.build.type={buildtype or '(empty)'}",
        remediation="No action.",
        title_de="Produktions-Build (user)",
        remediation_de="Keine Aktion nötig.",
        title_es="Build de producción (user)",
        remediation_es="Sin acción necesaria.",
        **base,
    )


# --- 1.5 Root / Magisk indicators ----------------------------------------------

ROOT_PATHS = ("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/magisk")


def _check_root_indicators(serial: str) -> Finding:
    hits: list[str] = []
    for p in ROOT_PATHS:
        if adb.shell(f"ls {p} 2>/dev/null", serial):
            hits.append(p)
    su_which = adb.shell("which su", serial)
    if su_which:
        hits.append(f"which su -> {su_which}")
    pkgs = adb.shell("pm list packages", serial)
    for line in pkgs.splitlines():
        low = line.lower()
        if "magisk" in low or "supersu" in low or "com.topjohnwu" in low:
            hits.append(line.strip())
    base = dict(
        id="ANDROID-CAT01-005",
        description="Looks for su binaries and root-manager packages (Magisk, SuperSU). Root massively expands what spyware can do: read any app's data, hide itself, survive resets.",
        category=CATEGORY,
        command="adb shell ls <su paths>; which su; pm list packages",
        vector_ids=("O-03", "M-01"),
        standards=("OWASP MASVS",),
        description_de="Sucht nach su-Binärdateien und Root-Manager-Paketen (Magisk, SuperSU). Root erweitert massiv, was Spyware kann: Daten jeder App lesen, sich verstecken, Resets überleben.",
        category_de=CATEGORY_DE,
        description_es="Busca binarios su y paquetes gestores de root (Magisk, SuperSU). El root expande enormemente lo que el spyware puede hacer: leer datos de cualquier app, ocultarse, sobrevivir restablecimientos.",
        category_es=CATEGORY_ES,
    )
    if hits:
        return Finding(
            title="Root / Magisk indicators present",
            severity=Severity.HIGH, status=Status.FAIL,
            evidence="\n".join(hits),
            remediation="If you rooted this phone yourself, you accepted this risk knowingly. If you did NOT, treat the device as compromised: back up personal data, factory reset, and change important passwords from a different, trusted device.",
            title_de="Root- / Magisk-Indikatoren vorhanden",
            remediation_de="Wenn du das Telefon selbst gerootet hast, kennst du dieses Risiko. Wenn NICHT, behandle das Gerät als kompromittiert: persönliche Daten sichern, auf Werkseinstellungen zurücksetzen und wichtige Passwörter von einem anderen, vertrauenswürdigen Gerät aus ändern.",
            title_es="Indicadores de root / Magisk presentes",
            remediation_es="Si rooteaste este teléfono tú, aceptaste el riesgo conscientemente. Si NO lo hiciste, trátalo como comprometido: respalda tus datos, restablece de fábrica y cambia las contraseñas importantes desde otro dispositivo confiable.",
            **base,
        )
    return Finding(
        title="No obvious root binaries detected",
        severity=Severity.INFO, status=Status.PASS,
        evidence="",
        remediation="No action.",
        title_de="Keine offensichtlichen Root-Binärdateien gefunden",
        remediation_de="Keine Aktion nötig.",
        title_es="No se detectaron binarios de root evidentes",
        remediation_es="Sin acción necesaria.",
        **base,
    )
