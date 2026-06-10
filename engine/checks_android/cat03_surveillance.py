"""CAT-3: Surveillance Surface & Persistence checks for Android (ADB, read-only).

Ported from android-triage.command (ACC-*, NTF-*, ADM-001, MSG-001):

  ANDROID-CAT03-001  accessibility services        HIGH (top stalkerware vector)
  ANDROID-CAT03-002  notification listeners        MEDIUM
  ANDROID-CAT03-003  device admin / owner apps     MEDIUM
  ANDROID-CAT03-004  default SMS handler           MEDIUM
"""
from __future__ import annotations

from ..core import Finding, ScanContext, Severity, Status, safe_check
from .. import adb

CATEGORY = "CAT-3: Surveillance Surface & Persistence"
CATEGORY_DE = "CAT-3: Überwachungsfläche & Persistenz"
CATEGORY_ES = "CAT-3: Superficie de vigilancia y persistencia"

STANDARD_SMS_APPS = (
    "com.google.android.apps.messaging",
    "com.android.messaging",
    "com.samsung.android.messaging",
)


def run(ctx: ScanContext) -> list[Finding]:
    serial = getattr(ctx, "target_serial", "") or ""
    out: list[Finding] = []
    out.append(safe_check("ANDROID-CAT03-001", CATEGORY, _check_accessibility, serial))
    out.append(safe_check("ANDROID-CAT03-002", CATEGORY, _check_notification_listeners, serial))
    out.append(safe_check("ANDROID-CAT03-003", CATEGORY, _check_device_admins, serial))
    out.append(safe_check("ANDROID-CAT03-004", CATEGORY, _check_default_sms, serial))
    return out


# --- 3.1 Accessibility services (the #1 stalkerware capability) ----------------

def _check_accessibility(serial: str) -> Finding:
    enabled_flag = adb.shell("settings get secure accessibility_enabled", serial)
    raw = adb.shell("settings get secure enabled_accessibility_services", serial)
    base = dict(
        id="ANDROID-CAT03-001",
        description="Accessibility services can read everything on screen and capture keystrokes. They are the number-one capability stalkerware abuses. Real assistive tools (TalkBack) legitimately use them; anything you do not recognize is a red flag.",
        category=CATEGORY,
        command="adb shell settings get secure enabled_accessibility_services",
        vector_ids=("M-02", "A-01"),
        standards=("OWASP MASVS", "Coalition Against Stalkerware"),
        description_de="Bedienungshilfen-Dienste können alles auf dem Bildschirm lesen und Tastatureingaben erfassen. Sie sind die wichtigste Fähigkeit, die Stalkerware missbraucht. Echte Assistenz-Tools (TalkBack) nutzen sie legitim; alles Unbekannte ist ein Alarmsignal.",
        category_de=CATEGORY_DE,
        description_es="Los servicios de accesibilidad pueden leer todo lo que hay en pantalla y capturar las teclas que escribes. Son la capacidad número uno que abusa el stalkerware. Las herramientas reales de asistencia (TalkBack) los usan legítimamente; cualquier cosa que no reconozcas es una alerta.",
        category_es=CATEGORY_ES,
    )
    if not raw or raw == "null":
        return Finding(
            title="No accessibility services enabled",
            severity=Severity.HIGH, status=Status.PASS,
            evidence=f"accessibility_enabled={enabled_flag or '0'}",
            remediation="No action.",
            title_de="Keine Bedienungshilfen-Dienste aktiviert",
            remediation_de="Keine Aktion nötig.",
            title_es="Sin servicios de accesibilidad habilitados",
            remediation_es="Sin acción necesaria.",
            **base,
        )
    services = [s for s in raw.split(":") if s]
    pkgs = sorted({s.split("/")[0] for s in services})
    return Finding(
        title=f"Accessibility service(s) enabled: {', '.join(pkgs)}",
        severity=Severity.HIGH, status=Status.WARN,
        evidence="\n".join(services),
        remediation="Verify you know each of these apps and enabled accessibility for it on purpose (screen readers and assistive tools are fine). If one is unknown: Settings > Accessibility > disable it, then uninstall the app.",
        title_de=f"Aktivierte Bedienungshilfen-Dienste: {', '.join(pkgs)}",
        remediation_de="Bestätige, dass du jede dieser Apps kennst und die Bedienungshilfe absichtlich aktiviert hast (Screenreader und Assistenz-Tools sind in Ordnung). Ist eine unbekannt: Einstellungen > Bedienungshilfen > deaktivieren, dann die App deinstallieren.",
        title_es=f"Servicio(s) de accesibilidad habilitados: {', '.join(pkgs)}",
        remediation_es="Verifica que conoces cada una de estas apps y que habilitaste la accesibilidad a propósito (lectores de pantalla y herramientas de asistencia están bien). Si alguna es desconocida: Ajustes > Accesibilidad > deshabilítala y luego desinstala la app.",
        **base,
    )


# --- 3.2 Notification listeners -------------------------------------------------

def _check_notification_listeners(serial: str) -> Finding:
    raw = adb.shell("settings get secure enabled_notification_listeners", serial)
    base = dict(
        id="ANDROID-CAT03-002",
        description="Notification listeners read every notification: messages, one-time codes, banking alerts. Smartwatch and automation apps use this legitimately; an unknown listener can silently exfiltrate your messages.",
        category=CATEGORY,
        command="adb shell settings get secure enabled_notification_listeners",
        vector_ids=("M-02", "E-01"),
        standards=("OWASP MASVS",),
        description_de="Benachrichtigungs-Listener lesen jede Benachrichtigung: Nachrichten, Einmal-Codes, Banking-Hinweise. Smartwatch- und Automations-Apps nutzen das legitim; ein unbekannter Listener kann deine Nachrichten still abgreifen.",
        category_de=CATEGORY_DE,
        description_es="Los lectores de notificaciones leen cada notificación: mensajes, códigos de un solo uso, alertas bancarias. Las apps de smartwatch y automatización lo usan legítimamente; un lector desconocido puede exfiltrar tus mensajes en silencio.",
        category_es=CATEGORY_ES,
    )
    if not raw or raw == "null":
        return Finding(
            title="No notification listeners enabled",
            severity=Severity.MEDIUM, status=Status.PASS,
            evidence="",
            remediation="No action.",
            title_de="Keine Benachrichtigungs-Listener aktiviert",
            remediation_de="Keine Aktion nötig.",
            title_es="Sin lectores de notificaciones habilitados",
            remediation_es="Sin acción necesaria.",
            **base,
        )
    services = [s for s in raw.split(":") if s]
    pkgs = sorted({s.split("/")[0] for s in services})
    return Finding(
        title=f"Notification listener(s) enabled: {', '.join(pkgs)}",
        severity=Severity.MEDIUM, status=Status.WARN,
        evidence="\n".join(services),
        remediation="Confirm each listener belongs to an app you use (watch, car, automation). If unknown: Settings > Notifications > Device & app notifications > revoke access, then uninstall the app.",
        title_de=f"Aktivierte Benachrichtigungs-Listener: {', '.join(pkgs)}",
        remediation_de="Bestätige, dass jeder Listener zu einer App gehört, die du nutzt (Uhr, Auto, Automation). Falls unbekannt: Einstellungen > Benachrichtigungen > Geräte- & App-Benachrichtigungen > Zugriff entziehen, dann die App deinstallieren.",
        title_es=f"Lector(es) de notificaciones habilitados: {', '.join(pkgs)}",
        remediation_es="Confirma que cada lector pertenece a una app que usas (reloj, auto, automatización). Si alguno es desconocido: Ajustes > Notificaciones > Notificaciones de apps y dispositivos > revoca el acceso y desinstala la app.",
        **base,
    )


# --- 3.3 Device admin / owner ----------------------------------------------------

def _check_device_admins(serial: str) -> Finding:
    policy = adb.shell("dumpsys device_policy", serial, timeout=25)
    owners = adb.shell("dpm list-owners", serial)
    admin_lines = [ln.strip() for ln in policy.splitlines()
                   if any(k in ln for k in ("Admin ", "Active admin", "Device Owner", "Profile Owner"))]
    base = dict(
        id="ANDROID-CAT03-003",
        description="Device admin and device owner apps resist uninstallation and can enforce policies. Find My Device and corporate MDM are legitimate; an unknown admin app is a classic stalkerware persistence trick.",
        category=CATEGORY,
        command="adb shell dumpsys device_policy; dpm list-owners",
        vector_ids=("M-02", "O-03"),
        standards=("OWASP MASVS",),
        description_de="Geräteadministrator- und Geräteinhaber-Apps widersetzen sich der Deinstallation und können Richtlinien erzwingen. 'Mein Gerät finden' und Firmen-MDM sind legitim; eine unbekannte Admin-App ist ein klassischer Stalkerware-Persistenztrick.",
        category_de=CATEGORY_DE,
        description_es="Las apps administradoras o propietarias del dispositivo resisten la desinstalación y pueden imponer políticas. 'Encontrar mi dispositivo' y el MDM corporativo son legítimos; una app administradora desconocida es un truco clásico de persistencia del stalkerware.",
        category_es=CATEGORY_ES,
    )
    evidence = "\n".join(admin_lines + ([owners] if owners else []))
    if evidence.strip():
        return Finding(
            title="Device admin / owner entries present",
            severity=Severity.MEDIUM, status=Status.WARN,
            evidence=evidence,
            remediation="Review the list. Find My Device and your employer's MDM are normal. Deactivate anything unknown (Settings > Security > Device admin apps), then uninstall it.",
            title_de="Geräteadministrator- / Inhaber-Einträge vorhanden",
            remediation_de="Prüfe die Liste. 'Mein Gerät finden' und das MDM deines Arbeitgebers sind normal. Deaktiviere alles Unbekannte (Einstellungen > Sicherheit > Geräteadministrator-Apps) und deinstalliere es danach.",
            title_es="Hay entradas de administrador / propietario del dispositivo",
            remediation_es="Revisa la lista. 'Encontrar mi dispositivo' y el MDM de tu trabajo son normales. Desactiva lo desconocido (Ajustes > Seguridad > Apps de administración del dispositivo) y luego desinstálalo.",
            **base,
        )
    return Finding(
        title="No unexpected device admin entries parsed",
        severity=Severity.MEDIUM, status=Status.PASS,
        evidence="",
        remediation="No action.",
        title_de="Keine unerwarteten Geräteadministrator-Einträge gefunden",
        remediation_de="Keine Aktion nötig.",
        title_es="No se detectaron entradas inesperadas de administrador",
        remediation_es="Sin acción necesaria.",
        **base,
    )


# --- 3.4 Default SMS handler -------------------------------------------------------

def _check_default_sms(serial: str) -> Finding:
    sms = adb.shell("settings get secure sms_default_application", serial)
    base = dict(
        id="ANDROID-CAT03-004",
        description="The default SMS app receives every text message, including one-time login codes. A rogue default SMS handler can intercept and forward them.",
        category=CATEGORY,
        command="adb shell settings get secure sms_default_application",
        vector_ids=("E-01", "A-02"),
        standards=("OWASP MASVS",),
        description_de="Die Standard-SMS-App empfängt jede Textnachricht, einschließlich Einmal-Login-Codes. Ein bösartiger Standard-SMS-Handler kann sie abfangen und weiterleiten.",
        category_de=CATEGORY_DE,
        description_es="La app de SMS predeterminada recibe cada mensaje de texto, incluidos los códigos de acceso de un solo uso. Un manejador de SMS malicioso puede interceptarlos y reenviarlos.",
        category_es=CATEGORY_ES,
    )
    if not sms or sms == "null" or sms in STANDARD_SMS_APPS:
        return Finding(
            title=f"Default SMS app looks standard ({sms or 'system default'})",
            severity=Severity.MEDIUM, status=Status.PASS,
            evidence=f"sms_default_application={sms or '(unset)'}",
            remediation="No action.",
            title_de=f"Standard-SMS-App sieht normal aus ({sms or 'Systemstandard'})",
            remediation_de="Keine Aktion nötig.",
            title_es=f"La app de SMS predeterminada parece estándar ({sms or 'predeterminada del sistema'})",
            remediation_es="Sin acción necesaria.",
            **base,
        )
    return Finding(
        title=f"Non-standard default SMS app: {sms}",
        severity=Severity.MEDIUM, status=Status.WARN,
        evidence=f"sms_default_application={sms}",
        remediation="Confirm this is a messenger you chose (e.g. Signal can be the SMS app on older Android). If you did not choose it, switch back: Settings > Apps > Default apps > SMS app, then investigate the app that held it.",
        title_de=f"Nicht-standardmäßige Standard-SMS-App: {sms}",
        remediation_de="Bestätige, dass du diesen Messenger gewählt hast (z. B. konnte Signal auf älterem Android die SMS-App sein). Falls nicht: Einstellungen > Apps > Standard-Apps > SMS-App zurückstellen und die betreffende App untersuchen.",
        title_es=f"App de SMS predeterminada no estándar: {sms}",
        remediation_es="Confirma que es un mensajero que tú elegiste (p. ej. Signal podía ser la app de SMS en Android antiguos). Si no la elegiste: Ajustes > Aplicaciones > Apps predeterminadas > App de SMS, y luego investiga la app que lo tenía.",
        **base,
    )
