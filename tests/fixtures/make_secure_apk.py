"""Forge a minimal APK that BioAudit's static analysis should rate clean.

Counterpart to make_sample_apk.py. Manifest: not debuggable, allowBackup=false, one
non-exported activity. DEX string pool carries onAuthenticationSucceeded,
CryptoObject and setUserAuthenticationRequired, so neither biometric rule fires.

    python tests/fixtures/make_secure_apk.py            # writes sample-secure-app.apk
    python -m bioaudit scan-apk sample-secure-app.apk --offline --no-report --fail-on high
"""

from __future__ import annotations

import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(__file__))
import make_sample_apk as m  # noqa: E402

PKG = "com.example.secure"


def build_manifest() -> bytes:
    attr_names = ["name", "allowBackup", "exported"]
    others = ["package", "android", m._ANDROID_NS, "manifest", "application",
              "activity", PKG, f"{PKG}.MainActivity"]
    strings = attr_names + others
    idx = {x: i for i, x in enumerate(strings)}
    res_ids = [m._RES_IDS[a] for a in attr_names]
    ns = idx[m._ANDROID_NS]

    def false_attr(name: str) -> bytes:   # android:<name>="false"
        return m._attr(ns, idx[name], None, m._TYPE_INT_BOOLEAN, 0)

    def start(name_idx: int, attrs: list[bytes]) -> bytes:
        body = struct.pack("<II", m._NO_ENTRY, name_idx)
        body += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0) + b"".join(attrs)
        return m._xml_node(0x0102, body)

    def end(name_idx: int) -> bytes:
        return m._xml_node(0x0103, struct.pack("<II", m._NO_ENTRY, name_idx))

    pkg_attr = m._attr(None, idx["package"], idx[PKG], m._TYPE_STRING, idx[PKG])
    act_name = m._attr(ns, idx["name"], idx[f"{PKG}.MainActivity"],
                       m._TYPE_STRING, idx[f"{PKG}.MainActivity"])
    parts = [
        m._xml_node(0x0100, struct.pack("<II", idx["android"], ns)),
        start(idx["manifest"], [pkg_attr]),
        start(idx["application"], [false_attr("allowBackup")]),
        start(idx["activity"], [act_name, false_attr("exported")]),
        end(idx["activity"]),
        end(idx["application"]),
        end(idx["manifest"]),
        m._xml_node(0x0101, struct.pack("<II", idx["android"], ns)),
    ]
    body = m._string_pool(strings) + m._resource_map(res_ids) + b"".join(parts)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def write_apk(path: str) -> str:
    dex = m.build_dex(extra_strings=("CryptoObject", "setUserAuthenticationRequired"))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", build_manifest())
        zf.writestr("classes.dex", dex)
    return path


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sample-secure-app.apk"
    write_apk(out)
    print(f"Wrote {out} ({os.path.getsize(out)} bytes)")
