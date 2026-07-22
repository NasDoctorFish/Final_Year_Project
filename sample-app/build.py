"""Build (and optionally install) the VulnDemo APK without Gradle.

Uses the Android SDK's own tools — aapt2, d8, zipalign, apksigner — plus javac.
Everything compiles in a temporary space-free directory because the Android .bat
tools mishandle spaces in paths (this repo lives under "…/Claude code/…").

    python sample-app/build.py                 # build -> sample-app/dist/vulndemo.apk
    python sample-app/build.py --install        # build, then `adb install -r`

Requires: a Java JDK (javac/keytool on PATH) and an Android SDK with build-tools
and a platform (android.jar). The SDK is auto-located; override with ANDROID_HOME.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MIN_SDK = "28"          # BiometricPrompt (framework) is API 28+
TARGET_SDK = "34"
PKG = "com.bioauthguard.vulndemo"


def find_sdk() -> Path:
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        p = os.environ.get(env)
        if p and Path(p).is_dir():
            return Path(p)
    default = Path(os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk"))
    if default.is_dir():
        return default
    for cand in (Path.home() / "Android/Sdk", Path.home() / "Library/Android/sdk"):
        if cand.is_dir():
            return cand
    sys.exit("Android SDK not found. Set ANDROID_HOME to your SDK path.")


def _version_key(name: str):
    parts = []
    for chunk in name.split("."):
        parts.append(int(chunk) if chunk.isdigit() else 0)
    return parts


def pick_build_tools(sdk: Path) -> Path:
    bt = sdk / "build-tools"
    versions = sorted((d for d in bt.iterdir() if d.is_dir()), key=lambda d: _version_key(d.name))
    if not versions:
        sys.exit(f"No build-tools under {bt}")
    return versions[-1]


def pick_android_jar(sdk: Path) -> Path:
    platforms = sdk / "platforms"
    jars = sorted(platforms.glob("android-*/android.jar"),
                  key=lambda p: _version_key(p.parent.name.split("-", 1)[-1]))
    if not jars:
        sys.exit(f"No platform android.jar under {platforms}")
    return jars[-1]


def tool(bt: Path, name: str) -> str:
    """Resolve a build-tool by name, trying .exe/.bat/bare on this OS."""
    for ext in (".exe", ".bat", ""):
        cand = bt / (name + ext)
        if cand.exists():
            return str(cand)
    sys.exit(f"Tool '{name}' not found in {bt}")


def run(cmd: list[str], cwd: Path | None = None) -> None:
    printable = " ".join(f'"{c}"' if " " in c else c for c in cmd)
    print("  $", printable[:200])
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        sys.exit(f"Command failed ({proc.returncode}): {cmd[0]}")


def main() -> int:
    install = "--install" in sys.argv
    sdk = find_sdk()
    bt = pick_build_tools(sdk)
    android_jar = pick_android_jar(sdk)
    aapt2 = tool(bt, "aapt2")
    d8 = tool(bt, "d8")
    zipalign = tool(bt, "zipalign")
    apksigner = tool(bt, "apksigner")
    print(f"SDK: {sdk}")
    print(f"build-tools: {bt.name}   platform: {android_jar.parent.name}")

    build = Path(tempfile.mkdtemp(prefix="vulndemo-build-"))
    try:
        # Copy sources into the space-free build dir.
        shutil.copytree(HERE / "res", build / "res")
        shutil.copytree(HERE / "src", build / "src")
        shutil.copy(HERE / "AndroidManifest.xml", build / "AndroidManifest.xml")

        print("[1/6] aapt2 compile resources")
        res_zip = build / "res.zip"
        run([aapt2, "compile", "--dir", str(build / "res"), "-o", str(res_zip)])

        print("[2/6] aapt2 link (base APK + R.java)")
        base_apk = build / "base.apk"
        gen = build / "gen"
        run([aapt2, "link", "-o", str(base_apk),
             "-I", str(android_jar),
             "--manifest", str(build / "AndroidManifest.xml"),
             "--java", str(gen),
             "--min-sdk-version", MIN_SDK, "--target-sdk-version", TARGET_SDK,
             "--version-code", "1", "--version-name", "1.0",
             str(res_zip)])

        print("[3/6] javac")
        classes = build / "classes"
        classes.mkdir()
        sources = glob.glob(str(build / "src" / "**" / "*.java"), recursive=True)
        sources += glob.glob(str(gen / "**" / "*.java"), recursive=True)
        run(["javac", "--release", "8", "-classpath", str(android_jar),
             "-d", str(classes), *sources])

        print("[4/6] d8 -> classes.dex")
        class_files = glob.glob(str(classes / "**" / "*.class"), recursive=True)
        run([d8, "--lib", str(android_jar), "--min-api", MIN_SDK,
             "--output", str(build), *class_files])
        # Merge classes.dex into the base APK.
        with zipfile.ZipFile(base_apk, "a", zipfile.ZIP_DEFLATED) as zf:
            zf.write(build / "classes.dex", "classes.dex")

        print("[5/6] zipalign")
        aligned = build / "aligned.apk"
        run([zipalign, "-f", "-p", "4", str(base_apk), str(aligned)])

        print("[6/6] sign (debug key)")
        keystore = build / "debug.keystore"
        run(["keytool", "-genkeypair", "-keystore", str(keystore),
             "-storepass", "android", "-keypass", "android",
             "-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048",
             "-validity", "10000", "-dname", "CN=BioAuthGuard Debug"])
        signed = build / "vulndemo-signed.apk"
        run([apksigner, "sign", "--ks", str(keystore),
             "--ks-pass", "pass:android", "--key-pass", "pass:android",
             "--out", str(signed), str(aligned)])

        # Copy the finished APK back into the repo (Python copy handles the space).
        out_dir = HERE / "dist"
        out_dir.mkdir(exist_ok=True)
        out_apk = out_dir / "vulndemo.apk"
        shutil.copy(signed, out_apk)
        print(f"\nBuilt: {out_apk}  ({out_apk.stat().st_size} bytes)")

        if install:
            sys.path.insert(0, str(HERE.parent))
            from bioauthguard.adb import resolve_adb  # reuse the tool's adb finder
            adb = resolve_adb("adb")
            print(f"\nInstalling with {adb} …")
            run([adb, "install", "-r", str(out_apk)])
            print("Installed. Launch 'BioAuthGuard VulnDemo' on the phone once, then assess:")
        print(f"\n  package: {PKG}")
        print(f"  apk:     {out_apk}")
        return 0
    finally:
        shutil.rmtree(build, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
