"""CAT-3 iOS: Surveillance surface, live (no backup required).

New checks for mobile-check (not in securityscan-usb):

  IOS-CAT03-001  passcode protection            HIGH
  IOS-CAT03-002  Developer Mode state           MEDIUM
  IOS-CAT03-003  Wi-Fi sync / wireless pairing  LOW

All read-only via lockdownd. Note the CAT-3 namespace matches mobile-check's
mobile category map (surveillance surface & persistence), not securityscan-usb.
"""
from __future__ import annotations

from ..core import Finding, ScanContext, Severity, Status, run_cmd, safe_check
from ..ios_backup import IPhoneInfo
from ..ios_toolchain import pymd3_path

CATEGORY = "CAT-3: Surveillance Surface & Persistence"
CATEGORY_DE = "CAT-3: Überwachungsfläche & Persistenz"
CATEGORY_ES = "CAT-3: Superficie de vigilancia y persistencia"


def run(ctx: ScanContext, *, phone: IPhoneInfo) -> list[Finding]:
    out: list[Finding] = []
    out.append(safe_check("IOS-CAT03-001", CATEGORY, _check_passcode, phone))
    out.append(safe_check("IOS-CAT03-002", CATEGORY, _check_developer_mode))
    out.append(safe_check("IOS-CAT03-003", CATEGORY, _check_wifi_sync))
    return out


# --- 3.1 Passcode protection ---------------------------------------------------

def _check_passcode(phone: IPhoneInfo) -> Finding:
    base = dict(
        id="IOS-CAT03-001",
        description="A passcode encrypts the device's data at rest and is the precondition for nearly every other iOS protection. lockdownd reports whether one is set.",
        category=CATEGORY,
        command="pymobiledevice3 lockdown info (PasswordProtected)",
        vector_ids=("F-01", "A-01"),
        standards=("Apple Platform Security",),
        description_de="Ein Code verschlüsselt die Gerätedaten und ist die Voraussetzung für fast jeden anderen iOS-Schutz. lockdownd meldet, ob einer gesetzt ist.",
        category_de=CATEGORY_DE,
        description_es="Un código de bloqueo cifra los datos del dispositivo en reposo y es la condición previa de casi toda otra protección de iOS. lockdownd reporta si hay uno configurado.",
        category_es=CATEGORY_ES,
    )
    if phone.password_protected:
        return Finding(
            title="A passcode is set",
            severity=Severity.HIGH, status=Status.PASS,
            evidence="PasswordProtected: true",
            remediation="No action. Prefer an alphanumeric passcode of 8+ characters for high-risk profiles.",
            title_de="Ein Code ist gesetzt",
            remediation_de="Keine Aktion nötig. Für Hochrisiko-Profile ist ein alphanumerischer Code mit 8+ Zeichen besser.",
            title_es="Hay un código de bloqueo configurado",
            remediation_es="Sin acción necesaria. Para perfiles de alto riesgo es mejor un código alfanumérico de 8+ caracteres.",
            **base,
        )
    return Finding(
        title="NO passcode is set on this iPhone",
        severity=Severity.HIGH, status=Status.FAIL,
        evidence="PasswordProtected: false",
        remediation="Set a passcode now: Settings > Face ID & Passcode > Turn Passcode On. Choose an alphanumeric code of 8+ characters. Without it, anyone with physical access has everything.",
        title_de="KEIN Code auf diesem iPhone gesetzt",
        remediation_de="Setze jetzt einen Code: Einstellungen > Face ID & Code > Code aktivieren. Wähle einen alphanumerischen Code mit 8+ Zeichen. Ohne Code hat jede Person mit physischem Zugriff alles.",
        title_es="NO hay código de bloqueo en este iPhone",
        remediation_es="Configura un código ahora: Ajustes > Face ID y código > Activar código. Elige un código alfanumérico de 8+ caracteres. Sin él, cualquiera con acceso físico lo tiene todo.",
        **base,
    )


# --- 3.2 Developer Mode ----------------------------------------------------------

def _check_developer_mode() -> Finding:
    pymd3 = pymd3_path()
    base = dict(
        id="IOS-CAT03-002",
        description="Developer Mode (iOS 16+) relaxes platform protections so a computer can install and debug apps. It should be OFF on a personal phone; finding it ON without explanation suggests someone prepared the device for tooling.",
        category=CATEGORY,
        command="pymobiledevice3 amfi developer-mode-status",
        vector_ids=("O-03", "F-01"),
        standards=("Apple Platform Security",),
        description_de="Der Entwicklermodus (iOS 16+) lockert Plattformschutz, damit ein Computer Apps installieren und debuggen kann. Auf einem privaten Telefon sollte er AUS sein; ist er ohne Erklärung AN, hat möglicherweise jemand das Gerät für Werkzeuge vorbereitet.",
        category_de=CATEGORY_DE,
        description_es="El Modo de Desarrollador (iOS 16+) relaja las protecciones de la plataforma para que una computadora pueda instalar y depurar apps. Debería estar APAGADO en un teléfono personal; encontrarlo ENCENDIDO sin explicación sugiere que alguien preparó el dispositivo para herramientas.",
        category_es=CATEGORY_ES,
    )
    if not pymd3:
        return Finding(
            title="Developer Mode: toolchain missing",
            severity=Severity.MEDIUM, status=Status.ERROR,
            evidence="pymobiledevice3 not available",
            remediation="Run the iOS setup, then re-scan. Manual check: Settings > Privacy & Security > Developer Mode.",
            title_de="Entwicklermodus: Werkzeuge fehlen",
            remediation_de="iOS-Einrichtung ausführen, dann erneut scannen. Manuell: Einstellungen > Datenschutz & Sicherheit > Entwicklermodus.",
            title_es="Modo de Desarrollador: faltan herramientas",
            remediation_es="Ejecuta la configuración de iOS y vuelve a analizar. Manual: Ajustes > Privacidad y seguridad > Modo de Desarrollador.",
            **base,
        )
    r = run_cmd([pymd3, "--no-color", "amfi", "developer-mode-status"], timeout=15)
    txt = (r.stdout + r.stderr).lower()
    if not r.ok and "true" not in txt and "false" not in txt:
        return Finding(
            title="Developer Mode state could not be queried",
            severity=Severity.MEDIUM, status=Status.ERROR,
            evidence=(r.stderr or r.stdout or r.exception)[:300],
            remediation="Manual check on the iPhone: Settings > Privacy & Security > Developer Mode (the entry only appears once a computer requested it; absence is good).",
            title_de="Entwicklermodus-Status nicht abfragbar",
            remediation_de="Manuell am iPhone: Einstellungen > Datenschutz & Sicherheit > Entwicklermodus (der Eintrag erscheint erst, wenn ein Computer ihn angefordert hat; Abwesenheit ist gut).",
            title_es="No se pudo consultar el Modo de Desarrollador",
            remediation_es="Revisión manual en el iPhone: Ajustes > Privacidad y seguridad > Modo de Desarrollador (la entrada solo aparece si una computadora lo solicitó; su ausencia es buena señal).",
            **base,
        )
    enabled = "true" in txt
    if enabled:
        return Finding(
            title="Developer Mode is ENABLED",
            severity=Severity.MEDIUM, status=Status.WARN,
            evidence=r.stdout.strip()[:200],
            remediation="If you are not an app developer, turn it off: Settings > Privacy & Security > Developer Mode > Off (the phone restarts). If you did not enable it, consider who had physical access to the device.",
            title_de="Entwicklermodus ist AKTIVIERT",
            remediation_de="Wenn du keine Apps entwickelst, schalte ihn aus: Einstellungen > Datenschutz & Sicherheit > Entwicklermodus > Aus (das Telefon startet neu). Hast du ihn nicht aktiviert, überlege, wer physischen Zugriff auf das Gerät hatte.",
            title_es="El Modo de Desarrollador está ACTIVADO",
            remediation_es="Si no desarrollas apps, apágalo: Ajustes > Privacidad y seguridad > Modo de Desarrollador > Desactivar (el teléfono se reinicia). Si tú no lo activaste, piensa quién tuvo acceso físico al dispositivo.",
            **base,
        )
    return Finding(
        title="Developer Mode is off",
        severity=Severity.MEDIUM, status=Status.PASS,
        evidence=r.stdout.strip()[:200] or "developer mode: false",
        remediation="No action.",
        title_de="Entwicklermodus ist aus",
        remediation_de="Keine Aktion nötig.",
        title_es="El Modo de Desarrollador está apagado",
        remediation_es="Sin acción necesaria.",
        **base,
    )


# --- 3.3 Wi-Fi sync / wireless pairing -------------------------------------------

def _check_wifi_sync() -> Finding:
    pymd3 = pymd3_path()
    base = dict(
        id="IOS-CAT03-003",
        description="Wi-Fi sync lets a previously trusted computer connect to this iPhone over the network, without a cable. Convenient, but it widens the surface: a compromised trusted computer can reach the phone whenever both share Wi-Fi.",
        category=CATEGORY,
        command="pymobiledevice3 lockdown info --domain com.apple.mobile.wireless_lockdown",
        vector_ids=("F-01", "N-01"),
        standards=("Apple Platform Security",),
        description_de="Wi-Fi-Sync erlaubt einem zuvor vertrauten Computer, sich ohne Kabel über das Netzwerk mit diesem iPhone zu verbinden. Bequem, aber es vergrößert die Fläche: Ein kompromittierter vertrauter Computer erreicht das Telefon, sobald beide im selben WLAN sind.",
        category_de=CATEGORY_DE,
        description_es="La sincronización por Wi-Fi permite que una computadora previamente confiable se conecte a este iPhone por la red, sin cable. Es cómodo, pero amplía la superficie: una computadora confiable comprometida puede alcanzar el teléfono cuando compartan Wi-Fi.",
        category_es=CATEGORY_ES,
    )
    if not pymd3:
        return Finding(
            title="Wi-Fi sync: toolchain missing",
            severity=Severity.LOW, status=Status.ERROR,
            evidence="pymobiledevice3 not available",
            remediation="Run the iOS setup, then re-scan.",
            title_de="Wi-Fi-Sync: Werkzeuge fehlen",
            remediation_de="iOS-Einrichtung ausführen, dann erneut scannen.",
            title_es="Sincronización Wi-Fi: faltan herramientas",
            remediation_es="Ejecuta la configuración de iOS y vuelve a analizar.",
            **base,
        )
    r = run_cmd([pymd3, "--no-color", "lockdown", "info",
                 "--domain", "com.apple.mobile.wireless_lockdown"], timeout=15)
    txt = (r.stdout or "").lower()
    if not r.ok or not txt.strip():
        return Finding(
            title="Wi-Fi sync state could not be queried",
            severity=Severity.LOW, status=Status.SKIP,
            evidence=(r.stderr or r.exception or "(empty)")[:200],
            remediation="MANUAL: in Finder (Mac) select the iPhone and check 'Show this iPhone when on Wi-Fi' is unchecked unless you use it.",
            title_de="Wi-Fi-Sync-Status nicht abfragbar",
            remediation_de="MANUELL: Im Finder (Mac) das iPhone auswählen und prüfen, dass 'Dieses iPhone im WLAN anzeigen' deaktiviert ist, sofern du es nicht nutzt.",
            title_es="No se pudo consultar la sincronización Wi-Fi",
            remediation_es="MANUAL: en Finder (Mac) selecciona el iPhone y verifica que 'Mostrar este iPhone por Wi-Fi' esté desmarcado salvo que lo uses.",
            **base,
        )
    enabled = '"enablewificonnections": true' in txt or "enablewificonnections: true" in txt
    if enabled:
        return Finding(
            title="Wi-Fi sync (wireless pairing) is enabled",
            severity=Severity.LOW, status=Status.WARN,
            evidence=r.stdout.strip()[:300],
            remediation="If you do not use wireless sync, disable it: connect to your computer, open Finder/iTunes, select the iPhone, uncheck 'Show this iPhone when on Wi-Fi'.",
            title_de="Wi-Fi-Sync (drahtloses Pairing) ist aktiviert",
            remediation_de="Wenn du drahtlosen Sync nicht nutzt, deaktiviere ihn: Mit dem Computer verbinden, Finder/iTunes öffnen, iPhone auswählen, 'Dieses iPhone im WLAN anzeigen' abwählen.",
            title_es="La sincronización Wi-Fi (emparejamiento inalámbrico) está activada",
            remediation_es="Si no usas la sincronización inalámbrica, desactívala: conecta a tu computadora, abre Finder/iTunes, selecciona el iPhone y desmarca 'Mostrar este iPhone por Wi-Fi'.",
            **base,
        )
    return Finding(
        title="Wi-Fi sync is not enabled",
        severity=Severity.LOW, status=Status.PASS,
        evidence=r.stdout.strip()[:300],
        remediation="No action.",
        title_de="Wi-Fi-Sync ist nicht aktiviert",
        remediation_de="Keine Aktion nötig.",
        title_es="La sincronización Wi-Fi no está activada",
        remediation_es="Sin acción necesaria.",
        **base,
    )
