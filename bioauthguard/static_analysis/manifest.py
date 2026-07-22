"""Parse an APK's manifest to enumerate exported components and security flags.

The exported-component list produced here is the input to the IPC authorization
oracle (the tool's headline runtime check).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..models import Finding, Severity


@dataclass
class Component:
    kind: str                       # "activity" | "service" | "receiver" | "provider"
    name: str
    exported: bool
    permission: Optional[str] = None
    has_intent_filter: bool = False
    authority: Optional[str] = None  # provider only: android:authorities (for content:// URIs)


@dataclass
class ManifestInfo:
    package: str
    debuggable: bool = False
    allow_backup: bool = True       # Android default is true when unset
    components: list[Component] = field(default_factory=list)

    def exported(self) -> list[Component]:
        return [c for c in self.components if c.exported]


_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _full_name(raw: str | None, package: str) -> Optional[str]:
    """Normalise a manifest android:name to a fully-qualified class name.

    Manifests store short forms (`.SecretActivity`, `SecretActivity`); resolve them
    against the package so downstream `am start -n <pkg>/<name>` calls are unambiguous.
    """
    if not raw:
        return raw
    if raw.startswith("."):
        return package + raw
    if "." not in raw:
        return f"{package}.{raw}"
    return raw


def parse_apk(apk_path: str) -> ManifestInfo:
    """Parse a manifest using androguard.

    Attributes are read directly off the manifest XML elements rather than via
    APK.get_attribute_value(..., name=...): androguard's getters return *full* class
    names while the manifest stores *short* ones (`.SecretActivity`), so name-matched
    lookups silently return None and every non-intent-filter export is missed.

    A component is treated as exported when `android:exported="true"`, or when it
    declares an intent-filter and does not set exported=false (Android's implicit
    export rule for pre-S targets).
    """
    from androguard.core.apk import APK  # imported lazily so `scan` works without a device

    apk = APK(apk_path)
    package = apk.get_package()
    manifest_xml = apk.get_android_manifest_xml()
    info = ManifestInfo(
        package=package,
        debuggable=bool(apk.get_attribute_value("application", "debuggable")),
        allow_backup=_attr_bool(apk.get_attribute_value("application", "allowBackup"), default=True),
    )

    for kind in ("activity", "service", "receiver", "provider"):
        for elem in manifest_xml.findall(f".//{kind}"):
            has_filter = elem.find("intent-filter") is not None
            exported = _attr_bool(elem.get(_ANDROID_NS + "exported"), default=None)
            if exported is None:
                exported = has_filter  # implicit export
            info.components.append(
                Component(
                    kind=kind,
                    name=_full_name(elem.get(_ANDROID_NS + "name"), package),
                    exported=bool(exported),
                    permission=elem.get(_ANDROID_NS + "permission"),
                    has_intent_filter=has_filter,
                    authority=(elem.get(_ANDROID_NS + "authorities") if kind == "provider" else None),
                )
            )
    return info


def manifest_findings(info: ManifestInfo) -> list[Finding]:
    """Config-level findings derivable from the manifest alone."""
    findings: list[Finding] = []

    if info.debuggable:
        findings.append(Finding(
            category="debuggable-release",
            title="Application is debuggable",
            severity=Severity.HIGH,
            owasp=["M8"],
            evidence="android:debuggable=\"true\" in the manifest",
            source="manifest",
            confidence="confirmed",
        ))

    if info.allow_backup:
        findings.append(Finding(
            category="allow-backup",
            title="allowBackup is enabled",
            severity=Severity.MEDIUM,
            owasp=["M9"],
            evidence="android:allowBackup is not set to false; app data may be extractable via `adb backup`",
            source="manifest",
            confidence="confirmed",
        ))

    for comp in info.exported():
        if comp.permission:
            continue  # guarded — reported only as info by the IPC oracle if reachable
        findings.append(Finding(
            category="exported-unguarded-component",
            title=f"Exported {comp.kind} without a permission guard",
            severity=Severity.MEDIUM,
            owasp=["M3"],
            evidence=f"{comp.kind} {comp.name} is exported with no android:permission",
            source="manifest",
            confidence="likely",
            component=comp.name,
        ))
    return findings


def _attr_bool(value, default):
    if value is None:
        return default
    return str(value).lower() == "true"
