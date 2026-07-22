"""Forge a tiny but *real* APK for exercising BioAuthGuard's static detectors.

There is no Android SDK on the dev box, so this hand-encodes the two things the
detectors actually parse:

  * a binary ``AndroidManifest.xml`` (Android's AXML chunk format) — deliberately
    insecure: debuggable, allowBackup, and an exported activity with no permission
    guard, plus a second exported-but-guarded activity to show the safe branch;
  * a minimal ``classes.dex`` whose one method is named ``onAuthenticationSucceeded``
    and which never references ``CryptoObject`` — the exact "boolean-only" biometric
    pattern ``static_analysis/apk_analyzer.py`` flags as HIGH.

The output is a plain ZIP (APK). androguard parses the manifest and decompiles the
dex without needing a signature. Run:

    python tests/fixtures/make_sample_apk.py            # writes sample-vuln-app.apk
    python -m bioauthguard scan-apk sample-vuln-app.apk

This is a synthetic app we generate ourselves — nothing proprietary, nothing you
need authorization to inspect.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import zlib

# --------------------------------------------------------------------------- #
# Binary AndroidManifest.xml (AXML) encoder
# --------------------------------------------------------------------------- #

# Framework attribute resource IDs (stable public values).
_RES_IDS = {
    "name": 0x01010003,
    "debuggable": 0x0101000F,
    "allowBackup": 0x01010280,
    "exported": 0x01010010,
    "permission": 0x01010006,
}

_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Res_value data types.
_TYPE_STRING = 0x03
_TYPE_INT_BOOLEAN = 0x12
_NO_ENTRY = 0xFFFFFFFF


def _string_pool(strings: list[str]) -> bytes:
    """UTF-16 string-pool chunk (flags=0), the classic aapt layout."""
    offsets = []
    data = bytearray()
    for s in strings:
        offsets.append(len(data))
        encoded = s.encode("utf-16-le")
        data += struct.pack("<H", len(s))          # length in UTF-16 code units
        data += encoded
        data += b"\x00\x00"                          # NUL terminator
    while len(data) % 4:
        data += b"\x00"

    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(data)
    chunk = struct.pack(
        "<HHIIIIII",
        0x0001,            # RES_STRING_POOL_TYPE
        header_size,
        size,
        len(strings),      # stringCount
        0,                 # styleCount
        0,                 # flags (0 = UTF-16)
        strings_start,
        0,                 # stylesStart
    )
    for off in offsets:
        chunk += struct.pack("<I", off)
    chunk += bytes(data)
    return chunk


def _resource_map(res_ids: list[int]) -> bytes:
    size = 8 + 4 * len(res_ids)
    chunk = struct.pack("<HHI", 0x0180, 8, size)     # RES_XML_RESOURCE_MAP_TYPE
    for rid in res_ids:
        chunk += struct.pack("<I", rid)
    return chunk


def _xml_node(node_type: int, body: bytes) -> bytes:
    header_size = 16
    size = header_size + len(body)
    head = struct.pack(
        "<HHIII",
        node_type,
        header_size,
        size,
        0,                 # lineNumber
        _NO_ENTRY,         # comment
    )
    return head + body


def _attr(ns_idx: int, name_idx: int, raw_idx: int, data_type: int, data: int) -> bytes:
    return struct.pack(
        "<III HBBI",
        ns_idx if ns_idx is not None else _NO_ENTRY,
        name_idx,
        raw_idx if raw_idx is not None else _NO_ENTRY,
        8,                 # Res_value size
        0,                 # res0
        data_type,
        data,
    )


def build_manifest() -> bytes:
    # String pool: framework attribute names first (indices align with the
    # resource map), then everything else.
    attr_names = ["name", "debuggable", "allowBackup", "exported", "permission"]
    others = [
        "package", "android", _ANDROID_NS, "manifest", "application", "activity",
        "com.example.vuln",                      # package
        "com.example.vuln.LoginActivity",        # exported, unguarded
        "com.example.vuln.AdminActivity",        # exported, guarded
        "com.example.vuln.permission.ADMIN",     # the guard
        "true",
    ]
    strings = attr_names + others
    idx = {s: i for i, s in enumerate(strings)}
    res_ids = [_RES_IDS[a] for a in attr_names]

    ns_uri = idx[_ANDROID_NS]

    def sattr(name: str, value: str) -> bytes:      # android:name="value" (string)
        return _attr(ns_uri, idx[name], idx[value], _TYPE_STRING, idx[value])

    def battr(name: str) -> bytes:                  # android:name="true" (boolean)
        return _attr(ns_uri, idx[name], idx["true"], _TYPE_INT_BOOLEAN, _NO_ENTRY)

    def start(name_idx: int, attrs: list[bytes], ns_idx: int | None = None) -> bytes:
        body = struct.pack("<II", ns_idx if ns_idx is not None else _NO_ENTRY, name_idx)
        body += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
        body += b"".join(attrs)
        return _xml_node(0x0102, body)              # START_ELEMENT

    def end(name_idx: int) -> bytes:
        return _xml_node(0x0103, struct.pack("<II", _NO_ENTRY, name_idx))

    # <manifest package="com.example.vuln">
    manifest_attr = _attr(None, idx["package"], idx["com.example.vuln"],
                          _TYPE_STRING, idx["com.example.vuln"])

    parts = [
        _xml_node(0x0100, struct.pack("<II", idx["android"], ns_uri)),   # START_NS
        start(idx["manifest"], [manifest_attr]),
        start(idx["application"], [battr("debuggable"), battr("allowBackup")]),
        start(idx["activity"], [sattr("name", "com.example.vuln.LoginActivity"),
                                battr("exported")]),
        end(idx["activity"]),
        start(idx["activity"], [sattr("name", "com.example.vuln.AdminActivity"),
                                battr("exported"),
                                sattr("permission", "com.example.vuln.permission.ADMIN")]),
        end(idx["activity"]),
        end(idx["application"]),
        end(idx["manifest"]),
        _xml_node(0x0101, struct.pack("<II", idx["android"], ns_uri)),   # END_NS
    ]

    body = _string_pool(strings) + _resource_map(res_ids) + b"".join(parts)
    size = 8 + len(body)
    return struct.pack("<HHI", 0x0003, 8, size) + body      # RES_XML_TYPE header


# --------------------------------------------------------------------------- #
# Minimal classes.dex encoder
# --------------------------------------------------------------------------- #

def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _align(buf: bytearray, boundary: int = 4) -> None:
    while len(buf) % boundary:
        buf.append(0)


def build_dex() -> bytes:
    # Strings must be sorted in code-point order for the string_ids table.
    strings = sorted([
        "Lcom/example/vuln/BioAuth;",
        "Ljava/lang/Object;",
        "V",
        "onAuthenticationSucceeded",
    ])
    s = {name: i for i, name in enumerate(strings)}

    # type_ids reference string indices; kept sorted by descriptor index.
    type_descs = ["Lcom/example/vuln/BioAuth;", "Ljava/lang/Object;", "V"]
    type_descs.sort(key=lambda d: s[d])
    t = {d: i for i, d in enumerate(type_descs)}

    header_size = 0x70
    off = header_size

    string_ids_off = off
    off += 4 * len(strings)
    type_ids_off = off
    off += 4 * len(type_descs)
    proto_ids_off = off
    off += 12 * 1
    method_ids_off = off
    off += 8 * 1
    class_defs_off = off
    off += 32 * 1

    # ---- data section ----
    data = bytearray()
    data_start = off

    # string_data_items (uleb128 length + MUTF-8 + NUL), remember absolute offsets.
    string_data_offsets = {}
    for name in strings:
        string_data_offsets[name] = data_start + len(data)
        encoded = name.encode("utf-8")
        data += _uleb128(len(name))       # length in UTF-16 units (ASCII == chars)
        data += encoded + b"\x00"

    # code_item: onAuthenticationSucceeded() { return; }. The decompiled signature
    # carries the method name, which is the token the analyzer's regex matches.
    _align(data, 4)
    code_off = data_start + len(data)
    data += struct.pack("<HHHH", 0, 0, 0, 0)   # registers, ins, outs, tries
    data += struct.pack("<I", 0)               # debug_info_off
    data += struct.pack("<I", 1)               # insns_size (code units)
    data += struct.pack("<H", 0x000E)          # return-void (opcode 0x0e, format 10x)

    # class_data_item
    _align(data, 1)
    class_data_off = data_start + len(data)
    data += _uleb128(0)      # static_fields_size
    data += _uleb128(0)      # instance_fields_size
    data += _uleb128(1)      # direct_methods_size
    data += _uleb128(0)      # virtual_methods_size
    data += _uleb128(0)      # method_idx_diff (first method)
    data += _uleb128(0x09)   # access_flags: public | static
    data += _uleb128(code_off)

    # map_list (4-aligned)
    _align(data, 4)
    map_off = data_start + len(data)
    map_items = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(type_descs), type_ids_off),
        (0x0003, 1, proto_ids_off),
        (0x0005, 1, method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2002, len(strings), string_data_offsets[strings[0]]),
        (0x2001, 1, code_off),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    data += struct.pack("<I", len(map_items))
    for type_code, count, item_off in map_items:
        data += struct.pack("<HHII", type_code, 0, count, item_off)

    data_size = len(data)
    file_size = data_start + data_size

    # ---- fixed tables ----
    string_ids = b"".join(struct.pack("<I", string_data_offsets[name]) for name in strings)
    type_ids = b"".join(struct.pack("<I", s[d]) for d in type_descs)

    proto_ids = struct.pack("<III", s["V"], t["V"], 0)   # shorty, return_type, params

    method_ids = struct.pack(
        "<HHI",
        t["Lcom/example/vuln/BioAuth;"],                 # class
        0,                                                # proto index
        s["onAuthenticationSucceeded"],                   # name
    )

    class_defs = struct.pack(
        "<IIIIIIII",
        t["Lcom/example/vuln/BioAuth;"],   # class_idx
        0x0001,                             # access_flags: public
        t["Ljava/lang/Object;"],           # superclass_idx
        0,                                  # interfaces_off
        _NO_ENTRY,                          # source_file_idx
        0,                                  # annotations_off
        class_data_off,                     # class_data_off
        0,                                  # static_values_off
    )

    # ---- header ----
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, file_size)
    struct.pack_into("<I", header, 0x24, header_size)
    struct.pack_into("<I", header, 0x28, 0x12345678)     # endian tag
    struct.pack_into("<I", header, 0x2C, 0)              # link_size
    struct.pack_into("<I", header, 0x30, 0)              # link_off
    struct.pack_into("<I", header, 0x34, map_off)
    struct.pack_into("<I", header, 0x38, len(strings))
    struct.pack_into("<I", header, 0x3C, string_ids_off)
    struct.pack_into("<I", header, 0x40, len(type_descs))
    struct.pack_into("<I", header, 0x44, type_ids_off)
    struct.pack_into("<I", header, 0x48, 1)              # proto_ids_size
    struct.pack_into("<I", header, 0x4C, proto_ids_off)
    struct.pack_into("<I", header, 0x50, 0)              # field_ids_size
    struct.pack_into("<I", header, 0x54, 0)              # field_ids_off
    struct.pack_into("<I", header, 0x58, 1)              # method_ids_size
    struct.pack_into("<I", header, 0x5C, method_ids_off)
    struct.pack_into("<I", header, 0x60, 1)              # class_defs_size
    struct.pack_into("<I", header, 0x64, class_defs_off)
    struct.pack_into("<I", header, 0x68, data_size)
    struct.pack_into("<I", header, 0x6C, data_start)

    body = bytes(header) + string_ids + type_ids + proto_ids + method_ids + class_defs + bytes(data)

    # Signature (SHA-1 over everything after the signature field, offset 0x20)
    # and checksum (Adler-32 over everything after the checksum field, offset 0x0C).
    body = bytearray(body)
    signature = hashlib.sha1(body[0x20:]).digest()
    body[0x0C:0x20] = signature
    checksum = zlib.adler32(bytes(body[0x0C:])) & 0xFFFFFFFF
    struct.pack_into("<I", body, 0x08, checksum)
    return bytes(body)


# --------------------------------------------------------------------------- #

def write_apk(path: str) -> str:
    import zipfile

    manifest = build_manifest()
    dex = build_dex()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
    return path


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "sample-vuln-app.apk"
    write_apk(out)
    print(f"Wrote {out} ({os.path.getsize(out)} bytes)")
    print("Try:  python -m bioauthguard scan-apk", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
