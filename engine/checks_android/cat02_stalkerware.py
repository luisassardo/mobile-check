"""CAT-2: Spyware & Stalkerware checks for Android (over ADB, read-only).

Ported from android-triage.command (APP-000, APP-SPY, APP-001..003) with the
same signals and severity logic, aggregated into one Finding per signal class
so the dashboard can dedupe by stable ID:

  ANDROID-CAT02-001  known-stalkerware package name match     CRITICAL
  ANDROID-CAT02-002  hidden-icon app holding spy permissions  HIGH
  ANDROID-CAT02-003  sideloaded app with broad spy permissions MEDIUM
  ANDROID-CAT02-004  app with many sensitive permissions       LOW
  ANDROID-CAT02-005  third-party app inventory                 INFO

The stalkerware hint list lives in engine/data/stalkerware_packages.json
(illustrative, NOT exhaustive — see Coalition Against Stalkerware / Echap).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..core import Finding, ScanContext, Severity, Status
from .. import adb
from ..progress import progress

CATEGORY = "CAT-2: Spyware & Stalkerware"
CATEGORY_DE = "CAT-2: Spyware & Stalkerware"
CATEGORY_ES = "CAT-2: Spyware y stalkerware"

SPY_PERMS = (
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.PACKAGE_USAGE_STATS",
)

PLAY_INSTALLERS = ("com.android.vending",)

# The DV-safety warning from android-triage, preserved verbatim in spirit.
SAFETY_NOTE_EN = ("If this may be an abusive-partner situation: removing spyware or alerting the "
                  "suspected abuser can escalate danger. Document findings first and reach a safety "
                  "plan (e.g. a local support organization) before changing anything on the device.")
SAFETY_NOTE_DE = ("Falls es sich um eine Situation mit übergriffigem Partner handeln könnte: Spyware zu "
                  "entfernen oder die verdächtigte Person zu alarmieren kann die Gefahr verschärfen. "
                  "Dokumentiere die Befunde zuerst und erstelle einen Sicherheitsplan (z. B. mit einer "
                  "lokalen Beratungsstelle), bevor du etwas am Gerät änderst.")
SAFETY_NOTE_ES = ("Si esta puede ser una situación de pareja abusiva: eliminar el spyware o alertar a la "
                  "persona sospechosa puede aumentar el peligro. Documenta los hallazgos primero y arma un "
                  "plan de seguridad (p. ej. con una organización local de apoyo) antes de cambiar algo en "
                  "el dispositivo.")


def run(ctx: ScanContext) -> list[Finding]:
    serial = getattr(ctx, "target_serial", "") or ""
    try:
        return _triage_apps(serial)
    except Exception as e:
        import traceback
        return [Finding(
            id="ANDROID-CAT02-CRASH",
            title="App triage crashed",
            description="An internal error prevented the app triage from running. This is a tool bug, not a finding about the phone.",
            category=CATEGORY,
            severity=Severity.INFO,
            status=Status.ERROR,
            command="engine.checks_android.cat02_stalkerware._triage_apps",
            evidence=f"{type(e).__name__}: {e}\n\nTraceback (truncated):\n{traceback.format_exc()[-1500:]}",
            remediation="Re-run the scan; if it persists, report this finding to the maintainer.",
            category_de=CATEGORY_DE,
            category_es=CATEGORY_ES,
        )]


def _load_stalker_hints() -> list[str]:
    p = Path(__file__).resolve().parent.parent / "data" / "stalkerware_packages.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return [h.lower() for h in data.get("hints", []) if h]
    except Exception:
        return []


def _third_party_packages(serial: str) -> list[dict]:
    """[{pkg, installer}] from `pm list packages -3 -i`."""
    raw = adb.shell("pm list packages -3 -i", serial, timeout=30)
    out: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        line = line[len("package:"):]
        parts = line.split()
        pkg = parts[0] if parts else ""
        installer = ""
        for p in parts[1:]:
            if p.startswith("installer="):
                installer = p.split("=", 1)[1]
        if pkg:
            out.append({"pkg": pkg, "installer": installer})
    return out


def _launcher_packages(serial: str) -> set[str]:
    raw = adb.shell(
        "cmd package query-activities -a android.intent.action.MAIN -c android.intent.category.LAUNCHER",
        serial, timeout=30)
    pkgs: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if "packageName=" in line:
            for tok in line.split():
                if tok.startswith("packageName="):
                    pkgs.add(tok.split("=", 1)[1])
    return pkgs


def _triage_apps(serial: str) -> list[Finding]:
    hints = _load_stalker_hints()
    apps = _third_party_packages(serial)
    launchers = _launcher_packages(serial)

    stalker_hits: list[str] = []
    hidden_spy: list[str] = []
    sideload_spy: list[str] = []
    perm_heavy: list[str] = []

    total = len(apps) or 1
    for i, app in enumerate(apps):
        pkg, installer = app["pkg"], app["installer"]
        if i % 5 == 0:
            progress("apps", int(30 + (i / total) * 50),
                     f"Analyzing apps ({i + 1}/{total})…",
                     f"Analizando apps ({i + 1}/{total})…",
                     f"Apps werden analysiert ({i + 1}/{total})…")

        lc = pkg.lower()
        matched = next((h for h in hints if h in lc), "")
        if matched:
            stalker_hits.append(f"{pkg} (matched={matched}, installer={installer or 'unknown'})")

        dump = adb.shell(f"dumpsys package {pkg}", serial, timeout=25)
        granted = [perm.rsplit(".", 1)[-1] for perm in SPY_PERMS if f"{perm}: granted=true" in dump]
        install_t = ""
        for line in dump.splitlines():
            if "firstInstallTime" in line:
                install_t = line.strip()
                break

        hidden = pkg not in launchers
        nperm = len(granted)
        detail = f"{pkg} (perms: {', '.join(granted) or 'none'}; installer={installer or 'unknown'}; {install_t})"

        if hidden and nperm > 0:
            hidden_spy.append(detail)
        elif nperm >= 3 and (not installer or installer in
                             ("null", "com.android.packageinstaller", "com.google.android.packageinstaller")):
            sideload_spy.append(detail)
        elif nperm >= 4:
            perm_heavy.append(detail)

    out: list[Finding] = []
    common = dict(category=CATEGORY, category_de=CATEGORY_DE, category_es=CATEGORY_ES,
                  standards=("Coalition Against Stalkerware", "OWASP MASVS"))

    # 02-001 known stalkerware -------------------------------------------------
    if stalker_hits:
        out.append(Finding(
            id="ANDROID-CAT02-001",
            title=f"Package name matches known-stalkerware list ({len(stalker_hits)})",
            description="One or more installed packages match names from public stalkerware lists. This is a strong indicator that commercial surveillance software is installed on this phone. " + SAFETY_NOTE_EN,
            severity=Severity.CRITICAL, status=Status.FAIL,
            command="adb shell pm list packages -3 -i",
            evidence="\n".join(stalker_hits),
            vector_ids=("M-02",),
            remediation="Document the finding (screenshots, this report) BEFORE removing anything. Then: Settings > Apps > remove the app's device-admin and accessibility rights, and uninstall it. If you are at risk, contact the Access Now Digital Security Helpline first.",
            references=("https://stopstalkerware.org/", "https://www.accessnow.org/help/"),
            title_de=f"Paketname stimmt mit bekannter Stalkerware-Liste überein ({len(stalker_hits)})",
            description_de="Mindestens ein installiertes Paket stimmt mit Namen aus öffentlichen Stalkerware-Listen überein. Das ist ein starker Hinweis auf kommerzielle Überwachungssoftware auf diesem Telefon. " + SAFETY_NOTE_DE,
            remediation_de="Dokumentiere den Befund (Screenshots, dieser Bericht), BEVOR du etwas entfernst. Danach: Einstellungen > Apps > Geräteadministrator- und Bedienungshilfen-Rechte der App entziehen und sie deinstallieren. Bist du gefährdet, kontaktiere zuerst die Digital Security Helpline von Access Now.",
            title_es=f"Nombre de paquete coincide con lista de stalkerware conocido ({len(stalker_hits)})",
            description_es="Uno o más paquetes instalados coinciden con nombres de listas públicas de stalkerware. Es un indicador fuerte de software comercial de vigilancia en este teléfono. " + SAFETY_NOTE_ES,
            remediation_es="Documenta el hallazgo (capturas, este informe) ANTES de eliminar nada. Luego: Ajustes > Aplicaciones > quita los permisos de administrador de dispositivo y accesibilidad de la app, y desinstálala. Si estás en riesgo, contacta primero la Línea de Ayuda de Access Now.",
            **common,
        ))
    else:
        out.append(Finding(
            id="ANDROID-CAT02-001",
            title="No package matches the known-stalkerware list",
            description="No installed package name matches the bundled list of known commercial stalkerware. The list is illustrative, not exhaustive: renamed or custom spyware will not match by name.",
            severity=Severity.CRITICAL, status=Status.PASS,
            command="adb shell pm list packages -3 -i",
            evidence=f"{len(apps)} third-party packages checked against {len(_load_stalker_hints())} hints",
            vector_ids=("M-02",),
            remediation="No action from this check. Review the other findings in this category.",
            references=("https://stopstalkerware.org/",),
            title_de="Kein Paket stimmt mit der bekannten Stalkerware-Liste überein",
            description_de="Kein installierter Paketname stimmt mit der mitgelieferten Liste bekannter kommerzieller Stalkerware überein. Die Liste ist beispielhaft, nicht vollständig: umbenannte oder maßgeschneiderte Spyware wird namentlich nicht erkannt.",
            remediation_de="Keine Aktion aus dieser Prüfung. Sieh dir die übrigen Befunde dieser Kategorie an.",
            title_es="Ningún paquete coincide con la lista de stalkerware conocido",
            description_es="Ningún nombre de paquete instalado coincide con la lista incluida de stalkerware comercial conocido. La lista es ilustrativa, no exhaustiva: spyware renombrado o hecho a medida no coincidirá por nombre.",
            remediation_es="Sin acción de esta verificación. Revisa los demás hallazgos de esta categoría.",
            **common,
        ))

    # 02-002 hidden icon + spy perms -------------------------------------------
    if hidden_spy:
        out.append(Finding(
            id="ANDROID-CAT02-002",
            title=f"Hidden-icon app(s) holding spy permissions ({len(hidden_spy)})",
            description="Apps with no launcher icon that hold camera, microphone, SMS or location access. No app-drawer icon plus surveillance permissions is the classic hidden-stalkerware signature. Some legitimate apps (keyboards, device services) also have no icon, so verify each one. " + SAFETY_NOTE_EN,
            severity=Severity.HIGH, status=Status.FAIL,
            command="adb shell dumpsys package <pkg>",
            evidence="\n".join(hidden_spy),
            vector_ids=("M-02",),
            remediation="Verify each listed app. If you do not recognize one: document it, then uninstall via Settings > Apps. Do not alert a potential abuser before a safety plan exists.",
            title_de=f"App(s) ohne Symbol mit Spionage-Berechtigungen ({len(hidden_spy)})",
            description_de="Apps ohne Launcher-Symbol mit Zugriff auf Kamera, Mikrofon, SMS oder Standort. Kein Symbol im App-Drawer plus Überwachungsberechtigungen ist die klassische Signatur versteckter Stalkerware. Manche legitime Apps (Tastaturen, Gerätedienste) haben ebenfalls kein Symbol, also prüfe jede einzeln. " + SAFETY_NOTE_DE,
            remediation_de="Prüfe jede gelistete App. Erkennst du eine nicht: dokumentieren, dann über Einstellungen > Apps deinstallieren. Alarmiere keine potenziell übergriffige Person, bevor ein Sicherheitsplan existiert.",
            title_es=f"App(s) sin ícono con permisos de espionaje ({len(hidden_spy)})",
            description_es="Apps sin ícono en el lanzador que tienen acceso a cámara, micrófono, SMS o ubicación. Sin ícono más permisos de vigilancia es la firma clásica del stalkerware oculto. Algunas apps legítimas (teclados, servicios del dispositivo) tampoco tienen ícono, así que verifica cada una. " + SAFETY_NOTE_ES,
            remediation_es="Verifica cada app listada. Si no reconoces alguna: documéntala y desinstálala desde Ajustes > Aplicaciones. No alertes a una persona potencialmente abusiva antes de tener un plan de seguridad.",
            **common,
        ))
    else:
        out.append(Finding(
            id="ANDROID-CAT02-002",
            title="No hidden-icon apps with spy permissions",
            description="No installed third-party app combines a missing launcher icon with surveillance-grade permissions.",
            severity=Severity.HIGH, status=Status.PASS,
            command="adb shell dumpsys package <pkg>",
            evidence=f"{len(apps)} third-party apps checked",
            vector_ids=("M-02",),
            remediation="No action.",
            title_de="Keine Apps ohne Symbol mit Spionage-Berechtigungen",
            description_de="Keine installierte Dritt-App kombiniert ein fehlendes Launcher-Symbol mit überwachungstauglichen Berechtigungen.",
            remediation_de="Keine Aktion nötig.",
            title_es="Sin apps ocultas con permisos de espionaje",
            description_es="Ninguna app de terceros instalada combina la falta de ícono con permisos de vigilancia.",
            remediation_es="Sin acción necesaria.",
            **common,
        ))

    # 02-003 sideloaded + >=3 spy perms ----------------------------------------
    if sideload_spy:
        out.append(Finding(
            id="ANDROID-CAT02-003",
            title=f"Sideloaded app(s) with broad spy permissions ({len(sideload_spy)})",
            description="Apps installed outside the Play Store that hold three or more sensitive permissions (microphone, camera, SMS, location...). Stalkerware is almost always sideloaded because Google bans it from the store.",
            severity=Severity.MEDIUM, status=Status.FAIL,
            command="adb shell dumpsys package <pkg>",
            evidence="\n".join(sideload_spy),
            vector_ids=("M-02", "M-01"),
            remediation="Confirm you installed each of these on purpose and trust their source. If not, uninstall them via Settings > Apps.",
            title_de=f"Sideload-App(s) mit weitreichenden Spionage-Berechtigungen ({len(sideload_spy)})",
            description_de="Apps, die außerhalb des Play Store installiert wurden und drei oder mehr sensible Berechtigungen halten (Mikrofon, Kamera, SMS, Standort ...). Stalkerware wird fast immer per Sideload installiert, weil Google sie im Store verbietet.",
            remediation_de="Bestätige, dass du jede davon absichtlich installiert hast und der Quelle vertraust. Falls nicht, deinstalliere sie über Einstellungen > Apps.",
            title_es=f"App(s) instaladas fuera de Play Store con permisos amplios ({len(sideload_spy)})",
            description_es="Apps instaladas fuera de Play Store que tienen tres o más permisos sensibles (micrófono, cámara, SMS, ubicación...). El stalkerware casi siempre se instala por sideload porque Google lo prohíbe en la tienda.",
            remediation_es="Confirma que instalaste cada una a propósito y confías en su origen. Si no, desinstálalas desde Ajustes > Aplicaciones.",
            **common,
        ))
    else:
        out.append(Finding(
            id="ANDROID-CAT02-003",
            title="No sideloaded apps with broad spy permissions",
            description="No app installed from outside the Play Store holds three or more sensitive permissions.",
            severity=Severity.MEDIUM, status=Status.PASS,
            command="adb shell dumpsys package <pkg>",
            evidence=f"{len(apps)} third-party apps checked",
            vector_ids=("M-02", "M-01"),
            remediation="No action.",
            title_de="Keine Sideload-Apps mit weitreichenden Spionage-Berechtigungen",
            description_de="Keine außerhalb des Play Store installierte App hält drei oder mehr sensible Berechtigungen.",
            remediation_de="Keine Aktion nötig.",
            title_es="Sin apps de sideload con permisos amplios de espionaje",
            description_es="Ninguna app instalada fuera de Play Store tiene tres o más permisos sensibles.",
            remediation_es="Sin acción necesaria.",
            **common,
        ))

    # 02-004 permission-heavy (LOW, only emitted when present) ------------------
    if perm_heavy:
        out.append(Finding(
            id="ANDROID-CAT02-004",
            title=f"App(s) with many sensitive permissions ({len(perm_heavy)})",
            description="Play-Store apps holding four or more sensitive permissions. Usually legitimate (messengers, navigation), but worth reviewing on a high-risk device.",
            severity=Severity.LOW, status=Status.WARN,
            command="adb shell dumpsys package <pkg>",
            evidence="\n".join(perm_heavy),
            vector_ids=("M-02",),
            remediation="Review whether each app genuinely needs all of these permissions. Revoke unneeded ones: Settings > Apps > (app) > Permissions.",
            title_de=f"App(s) mit vielen sensiblen Berechtigungen ({len(perm_heavy)})",
            description_de="Play-Store-Apps mit vier oder mehr sensiblen Berechtigungen. Meist legitim (Messenger, Navigation), aber auf einem Hochrisiko-Gerät eine Überprüfung wert.",
            remediation_de="Prüfe, ob jede App all diese Berechtigungen wirklich braucht. Entziehe unnötige: Einstellungen > Apps > (App) > Berechtigungen.",
            title_es=f"App(s) con muchos permisos sensibles ({len(perm_heavy)})",
            description_es="Apps de Play Store con cuatro o más permisos sensibles. Normalmente legítimas (mensajería, navegación), pero vale revisarlas en un dispositivo de alto riesgo.",
            remediation_es="Revisa si cada app realmente necesita todos esos permisos. Revoca los innecesarios: Ajustes > Aplicaciones > (app) > Permisos.",
            **common,
        ))

    # 02-005 inventory (INFO) ----------------------------------------------------
    out.append(Finding(
        id="ANDROID-CAT02-005",
        title=f"{len(apps)} third-party (user-installed) apps found",
        description="Inventory of user-installed apps considered by this category. System apps are excluded.",
        severity=Severity.INFO, status=Status.PASS,
        command="adb shell pm list packages -3 -i",
        evidence="\n".join(f"{a['pkg']} (installer={a['installer'] or 'unknown'})" for a in apps[:60])
                 + ("\n…" if len(apps) > 60 else ""),
        vector_ids=("M-02",),
        remediation="No action. This entry documents what was scanned.",
        title_de=f"{len(apps)} Dritt-Apps (vom Nutzer installiert) gefunden",
        description_de="Inventar der nutzerinstallierten Apps, die diese Kategorie betrachtet hat. System-Apps sind ausgenommen.",
        remediation_de="Keine Aktion nötig. Dieser Eintrag dokumentiert, was geprüft wurde.",
        title_es=f"{len(apps)} apps de terceros (instaladas por el usuario) encontradas",
        description_es="Inventario de las apps instaladas por el usuario que consideró esta categoría. Las apps del sistema quedan excluidas.",
        remediation_es="Sin acción necesaria. Esta entrada documenta lo que se analizó.",
        **common,
    ))
    return out
