"""CAT-4: Network & Interception checks for Android (ADB, read-only).

Ported from android-triage.command (NET-001, NET-002, CRT-001):

  ANDROID-CAT04-001  global HTTP proxy            HIGH
  ANDROID-CAT04-002  always-on VPN                MEDIUM
  ANDROID-CAT04-003  user-installed CA certs      HIGH (SKIP without root)
"""
from __future__ import annotations

from ..core import Finding, ScanContext, Severity, Status, safe_check
from .. import adb

CATEGORY = "CAT-4: Network & Interception"
CATEGORY_DE = "CAT-4: Netzwerk & Abhören"
CATEGORY_ES = "CAT-4: Red e interceptación"


def run(ctx: ScanContext) -> list[Finding]:
    serial = getattr(ctx, "target_serial", "") or ""
    out: list[Finding] = []
    out.append(safe_check("ANDROID-CAT04-001", CATEGORY, _check_global_proxy, serial))
    out.append(safe_check("ANDROID-CAT04-002", CATEGORY, _check_always_on_vpn, serial))
    out.append(safe_check("ANDROID-CAT04-003", CATEGORY, _check_user_ca_certs, serial))
    return out


def _check_global_proxy(serial: str) -> Finding:
    proxy = adb.shell("settings get global http_proxy", serial)
    base = dict(
        id="ANDROID-CAT04-001",
        description="A device-wide HTTP proxy routes traffic through a third machine, which can inspect or alter it. Normal phones have no global proxy set.",
        category=CATEGORY,
        command="adb shell settings get global http_proxy",
        vector_ids=("N-01",),
        standards=("OWASP MASVS",),
        description_de="Ein gerätweiter HTTP-Proxy leitet den Datenverkehr über einen dritten Rechner, der ihn einsehen oder verändern kann. Normale Telefone haben keinen globalen Proxy gesetzt.",
        category_de=CATEGORY_DE,
        description_es="Un proxy HTTP a nivel de dispositivo enruta el tráfico por una tercera máquina, que puede inspeccionarlo o alterarlo. Los teléfonos normales no tienen proxy global configurado.",
        category_es=CATEGORY_ES,
    )
    if proxy and proxy not in ("null", ":0"):
        return Finding(
            title=f"Global HTTP proxy configured: {proxy}",
            severity=Severity.HIGH, status=Status.FAIL,
            evidence=f"http_proxy={proxy}",
            remediation="If you did not set this proxy (or your organization did not), remove it: Settings > Network & internet > Wi-Fi > (network) > Proxy > None. Then investigate how it got there.",
            title_de=f"Globaler HTTP-Proxy konfiguriert: {proxy}",
            remediation_de="Wenn du (oder deine Organisation) diesen Proxy nicht gesetzt hast, entferne ihn: Einstellungen > Netzwerk & Internet > WLAN > (Netzwerk) > Proxy > Keiner. Untersuche danach, wie er dorthin kam.",
            title_es=f"Proxy HTTP global configurado: {proxy}",
            remediation_es="Si tú (o tu organización) no configuraron este proxy, elimínalo: Ajustes > Redes e internet > Wi-Fi > (red) > Proxy > Ninguno. Luego investiga cómo llegó ahí.",
            **base,
        )
    return Finding(
        title="No global HTTP proxy set",
        severity=Severity.HIGH, status=Status.PASS,
        evidence=f"http_proxy={proxy or '(unset)'}",
        remediation="No action.",
        title_de="Kein globaler HTTP-Proxy gesetzt",
        remediation_de="Keine Aktion nötig.",
        title_es="Sin proxy HTTP global configurado",
        remediation_es="Sin acción necesaria.",
        **base,
    )


def _check_always_on_vpn(serial: str) -> Finding:
    vpn = adb.shell("settings get secure always_on_vpn_app", serial)
    base = dict(
        id="ANDROID-CAT04-002",
        description="An always-on VPN forces all traffic through one app. Privacy VPNs you chose are legitimate; an unknown forced VPN can funnel everything to an attacker.",
        category=CATEGORY,
        command="adb shell settings get secure always_on_vpn_app",
        vector_ids=("N-01", "N-02"),
        standards=("OWASP MASVS",),
        description_de="Ein Always-on-VPN zwingt sämtlichen Datenverkehr durch eine App. Selbst gewählte Privatsphäre-VPNs sind legitim; ein unbekanntes erzwungenes VPN kann alles zu einem Angreifer leiten.",
        category_de=CATEGORY_DE,
        description_es="Una VPN siempre activa fuerza todo el tráfico por una sola app. Las VPN de privacidad que tú elegiste son legítimas; una VPN forzada desconocida puede canalizar todo hacia un atacante.",
        category_es=CATEGORY_ES,
    )
    if vpn and vpn != "null":
        return Finding(
            title=f"Always-on VPN app set: {vpn}",
            severity=Severity.MEDIUM, status=Status.WARN,
            evidence=f"always_on_vpn_app={vpn}",
            remediation="Confirm this is a VPN you installed and trust. If unknown: Settings > Network & internet > VPN > review and remove it.",
            title_de=f"Always-on-VPN-App gesetzt: {vpn}",
            remediation_de="Bestätige, dass dies ein VPN ist, das du installiert hast und dem du vertraust. Falls unbekannt: Einstellungen > Netzwerk & Internet > VPN > prüfen und entfernen.",
            title_es=f"App de VPN siempre activa configurada: {vpn}",
            remediation_es="Confirma que es una VPN que instalaste y en la que confías. Si es desconocida: Ajustes > Redes e internet > VPN > revísala y elimínala.",
            **base,
        )
    return Finding(
        title="No always-on VPN forced",
        severity=Severity.MEDIUM, status=Status.PASS,
        evidence="",
        remediation="No action.",
        title_de="Kein Always-on-VPN erzwungen",
        remediation_de="Keine Aktion nötig.",
        title_es="Sin VPN siempre activa forzada",
        remediation_es="Sin acción necesaria.",
        **base,
    )


def _check_user_ca_certs(serial: str) -> Finding:
    certs = adb.shell("ls /data/misc/user/0/cacerts-added/ 2>/dev/null", serial)
    base = dict(
        id="ANDROID-CAT04-003",
        description="User-installed root certificates let whoever installed them intercept HTTPS traffic (man-in-the-middle). A normal personal phone has zero user CAs. Enumerating the store over ADB usually requires root, so this check may need a manual step.",
        category=CATEGORY,
        command="adb shell ls /data/misc/user/0/cacerts-added/",
        vector_ids=("N-01", "W-01"),
        standards=("OWASP MASVS",),
        description_de="Vom Nutzer installierte Stammzertifikate erlauben dem, der sie installiert hat, HTTPS-Verkehr abzufangen (Man-in-the-Middle). Ein normales privates Telefon hat null Nutzer-CAs. Die Auflistung über ADB erfordert meist Root, daher kann diese Prüfung einen manuellen Schritt brauchen.",
        category_de=CATEGORY_DE,
        description_es="Los certificados raíz instalados por el usuario permiten a quien los instaló interceptar el tráfico HTTPS (man-in-the-middle). Un teléfono personal normal tiene cero CA de usuario. Enumerar el almacén por ADB suele requerir root, así que esta verificación puede necesitar un paso manual.",
        category_es=CATEGORY_ES,
    )
    if certs:
        return Finding(
            title="User-installed CA certificate(s) present",
            severity=Severity.HIGH, status=Status.FAIL,
            evidence=certs,
            remediation="Remove any certificate you do not recognize: Settings > Security > Encryption & credentials > User credentials / Trusted credentials > User tab. Corporate Wi-Fi or MDM certs may be legitimate; ask your IT contact.",
            title_de="Vom Nutzer installierte CA-Zertifikate vorhanden",
            remediation_de="Entferne jedes Zertifikat, das du nicht erkennst: Einstellungen > Sicherheit > Verschlüsselung & Anmeldedaten > Nutzeranmeldedaten / Vertrauenswürdige Anmeldedaten > Tab 'Nutzer'. Firmen-WLAN- oder MDM-Zertifikate können legitim sein; frag deine IT.",
            title_es="Hay certificado(s) CA instalados por el usuario",
            remediation_es="Elimina cualquier certificado que no reconozcas: Ajustes > Seguridad > Cifrado y credenciales > Credenciales de usuario / Credenciales de confianza > pestaña Usuario. Los certificados de Wi-Fi corporativo o MDM pueden ser legítimos; consulta a tu contacto de TI.",
            **base,
        )
    return Finding(
        title="Could not enumerate the user CA store over ADB (no root)",
        severity=Severity.MEDIUM, status=Status.SKIP,
        evidence="",
        remediation="MANUAL CHECK: open Settings > Security > Encryption & credentials > Trusted credentials > USER tab. There should normally be ZERO entries. Remove anything unexpected.",
        title_de="Nutzer-CA-Speicher konnte über ADB nicht aufgelistet werden (kein Root)",
        remediation_de="MANUELL PRÜFEN: Öffne Einstellungen > Sicherheit > Verschlüsselung & Anmeldedaten > Vertrauenswürdige Anmeldedaten > Tab NUTZER. Normalerweise sollten dort NULL Einträge stehen. Entferne alles Unerwartete.",
        title_es="No se pudo enumerar el almacén de CA de usuario por ADB (sin root)",
        remediation_es="VERIFICACIÓN MANUAL: abre Ajustes > Seguridad > Cifrado y credenciales > Credenciales de confianza > pestaña USUARIO. Normalmente debe haber CERO entradas. Elimina cualquier cosa inesperada.",
        **base,
    )
