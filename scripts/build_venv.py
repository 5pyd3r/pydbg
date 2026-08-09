#!/usr/bin/env python3
"""Build pydbg with venv Python, handling Git/MSVC PATH conflicts.

x64-only: pydbg is built for a 64-bit host (WOW64 32-bit targets are
supported for debugging, but the extension itself is always x64).
"""
import subprocess
import os
import sys
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# MSVC paths
MSVC_BIN = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\HostX64\x64"
MSVC_INCLUDE = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\include"
MSVC_LIB = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\lib\x64"
SDK_INCLUDE = r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
SDK_LIB = r"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0"


def clean_path():
    """Remove Git usr/bin from PATH to avoid GNU link.exe conflict."""
    path = os.environ.get("PATH", "")
    parts = path.split(";")
    clean = [p for p in parts if "Git\\usr\\bin" not in p and "Git/usr/bin" not in p]
    return ";".join(clean)


def setup_env():
    """Set up the x64 build environment with MSVC tools."""
    venv_scripts = os.path.join(ROOT, "venv-x64", "Scripts")
    env = os.environ.copy()
    env["PATH"] = venv_scripts + ";" + MSVC_BIN + ";" + clean_path()
    env["INCLUDE"] = ";".join([
        MSVC_INCLUDE,
        os.path.join(SDK_INCLUDE, "ucrt"),
        os.path.join(SDK_INCLUDE, "shared"),
        os.path.join(SDK_INCLUDE, "um"),
        os.path.join(SDK_INCLUDE, "winrt"),
    ])
    env["LIB"] = ";".join([
        MSVC_LIB,
        os.path.join(SDK_LIB, "ucrt", "x64"),
        os.path.join(SDK_LIB, "um", "x64"),
    ])
    return env


def build():
    """Build pydbg for x64."""
    venv = os.path.join(ROOT, "venv-x64")
    meson = os.path.join(venv, "Scripts", "meson.exe")
    build_dir = os.path.join(ROOT, "build-venv-x64")
    python = os.path.join(venv, "Scripts", "python.exe")

    if not os.path.exists(meson):
        print("[error] venv-x64 not found. Run setup_venv.ps1 first.")
        return False

    env = setup_env()

    # Clean old build
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)

    # Setup
    print("[configure] meson setup build-venv-x64")
    cmd = [meson, "setup", build_dir, "--buildtype=release"]
    r = subprocess.run(cmd, env=env, cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[fail] setup:\n{r.stderr[-500:]}")
        return False

    # Compile
    print("[build] meson compile -C build-venv-x64")
    r = subprocess.run([meson, "compile", "-C", build_dir], env=env, cwd=ROOT,
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[fail] compile:\n{r.stderr[-500:]}")
        return False

    # Install: copy built .pyd to src/pydbg/ so it's importable
    print("[install] copying built extension")
    import glob
    pyd_pattern = os.path.join(build_dir, "src", "pydbg", "cython", "_pydbg*.pyd")
    pyd_files = glob.glob(pyd_pattern)
    if pyd_files:
        for pyd in pyd_files:
            dst = os.path.join(ROOT, "src", "pydbg", os.path.basename(pyd))
            shutil.copy2(pyd, dst)
            # Also copy as _pydbg.pyd for import compatibility
            shutil.copy2(pyd, os.path.join(ROOT, "src", "pydbg", "_pydbg.pyd"))
            print(f"  copied {os.path.basename(pyd)}")
    else:
        print(f"[warn] no .pyd found in {pyd_pattern}")

    # Copy test target executables
    test_target = os.path.join(build_dir, "tests", "simple_target.exe")
    if os.path.exists(test_target):
        target_name = "simple_target_x64.exe"
        dst = os.path.join(ROOT, "tests", "target", target_name)
        shutil.copy2(test_target, dst)
        print(f"  copied {target_name}")

    # Test: run with PYTHONPATH=src so pydbg is importable
    print("[test] running tests")
    test_env = env.copy()
    test_env["PYTHONPATH"] = os.path.join(ROOT, "src")
    test_env["TEST_TARGET_PATH"] = os.path.join(ROOT, "tests", "target", "simple_target_x64.exe")
    test_env["TEST_CHILD_TARGET"] = os.path.join(ROOT, "tests", "target", "child_target_x64.exe")
    r = subprocess.run(
        [python, "-m", "unittest", "tests.test_process", "tests.test_memory",
         "tests.test_thread", "tests.test_breakpoint", "tests.test_debugger",
         "tests.test_pe", "tests.test_trace", "tests.test_dump", "tests.test_hook",
         "tests.test_comprehensive", "tests.test_child_process"],
        env=test_env, cwd=ROOT, capture_output=True, text=True
    )
    # Print summary
    for line in (r.stdout + r.stderr).split("\n"):
        if "Ran" in line or "FAIL" in line or "ERROR" in line or "OK" in line or "skip" in line:
            print(line)
    if r.returncode != 0:
        print("[fail] tests failed")
        return False

    print("[pass] build-venv-x64 OK")
    return True


if __name__ == "__main__":
    sys.exit(0 if build() else 1)
