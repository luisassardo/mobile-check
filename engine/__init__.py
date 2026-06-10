"""MobileCheck engine package — the mobile sibling of ComputerCheck.

Scans the user's own phone over USB: Android via adb (checks ported from
../android-triage), iOS via pymobiledevice3 + MVT (vendored from
../securityscan-usb). Shares the Finding model and reporters with the rest of
the SecurityScan family as a vendored copy per CONVENTIONS.md (no shared
library until the tools reach v1.0).
"""
__version__ = "0.1.0"
