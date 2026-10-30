import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell.exe")
pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not POWERSHELL, reason="Windows PowerShell required"
)


def run_script(script, *args, env=None):
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *args],
        capture_output=True,
        text=True,
        timeout=45,
        cwd=script.parent.parent,
        env=env,
        check=False,
    )


@pytest.fixture
def checkout(tmp_path):
    checkout = tmp_path / "checkout with spaces"
    checkout.mkdir()
    for name in ("run_specterlan.ps1", "setup_windows.ps1"):
        shutil.copyfile(ROOT / name, checkout / name)
    return checkout


def test_missing_venv_has_setup_instructions(checkout):
    result = run_script(checkout / "run_specterlan.ps1", "-Check")
    assert result.returncode == 1
    assert "setup_windows.ps1" in result.stdout


@pytest.mark.parametrize("system_packages", [False, True])
def test_launcher_preflight_uses_its_own_environment_from_other_directory(
    checkout, system_packages
):
    args = [sys.executable, "-m", "venv", "--without-pip"]
    if system_packages:
        args.append("--system-site-packages")
    subprocess.run([*args, str(checkout / ".venv")], check=True, capture_output=True, timeout=45)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    result = run_script(checkout / "run_specterlan.ps1", "-Check", env=env)
    if system_packages:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "launcher check passed" in result.stdout
    else:
        assert result.returncode == 1
        assert "dependencies are missing or broken" in result.stdout
        assert "setup_windows.ps1" in result.stdout


def test_setup_reports_invalid_python_without_installing_system_software(checkout):
    result = run_script(checkout / "setup_windows.ps1", "-Python", "nonexistent-python-command")
    assert result.returncode == 1
    assert "setup failed" in result.stdout
    assert not (checkout / ".venv").exists()


def test_real_launcher_serves_loopback_health_without_onboarding(checkout):
    subprocess.run(
        [
            sys.executable,
            "-m",
            "venv",
            "--without-pip",
            "--system-site-packages",
            str(checkout / ".venv"),
        ],
        check=True,
        capture_output=True,
        timeout=45,
    )
    # Use a tiny Streamlit script: the HTTP smoke test must never scan the real LAN.
    (checkout / "app.py").write_text("import streamlit as st\nst.title('Launcher smoke test')\n")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env = dict(os.environ, PYTHONPATH=str(ROOT), STREAMLIT_SERVER_PORT=str(port))
    process = subprocess.Popen(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(checkout / "run_specterlan.ps1"),
        ],
        cwd=checkout.parent,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        deadline = time.monotonic() + 25
        with httpx.Client(trust_env=False, timeout=1.0) as client:
            while time.monotonic() < deadline:
                assert process.poll() is None, process.communicate()[0]
                try:
                    response = client.get(f"http://127.0.0.1:{port}/_stcore/health")
                    if response.status_code == 200:
                        assert response.text == "ok"
                        assert client.get(f"http://127.0.0.1:{port}/").status_code == 200
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.2)
            else:
                pytest.fail("Local Streamlit health endpoint did not become ready")
    finally:
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            capture_output=True,
            timeout=10,
        )
        process.communicate(timeout=10)


@pytest.mark.parametrize("name", ["run_specterlan.ps1", "setup_windows.ps1"])
def test_powershell_syntax(name):
    # Send the path as an argument, never interpolate it into PowerShell code.
    command = (
        "$tokens = $null; $errors = $null; "
        "[System.Management.Automation.Language.Parser]::ParseFile("
        "$env:SPECTERLAN_SCRIPT_TEST_PATH, [ref]$tokens, [ref]$errors) | Out-Null; "
        "if ($errors.Count) { $errors | Out-String | Write-Output; exit 1 }"
    )
    env = dict(os.environ, SPECTERLAN_SCRIPT_TEST_PATH=str(ROOT / name))
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-Command", command],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
