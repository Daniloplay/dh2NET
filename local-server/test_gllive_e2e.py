"""Automated end-to-end test: dh2_local_server.py + dh2_win_headless.exe."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_PY = ROOT / "local-server" / "dh2_local_server.py"
HEADLESS_EXE = ROOT / "b" / "host-runner" / "dh2_win_headless.exe"
DATA_DIR = ROOT / "Dungeon-Hunter-2-source-code-1.0.0" / "Dungeon-Hunter-2-source-code-1.0.0" / "build_data" / "files"


def main() -> int:
    script_text = """\
300 mp init 3
330 mp login d 8
450 mp create
550 mp start
650 mp status
750 mp status
850 quit
"""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write(script_text)
        script_path = Path(tf.name)

    srv = subprocess.Popen(
        [sys.executable, "-u", str(SERVER_PY)],
        cwd=str(SERVER_PY.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(1.0)
    try:
        env = os.environ.copy()
        env["DH2_FORCE_TCP"] = "1"
        game = subprocess.run(
            [
                str(HEADLESS_EXE),
                "--data",
                str(DATA_DIR),
                "--script",
                str(script_path),
                "--frames",
                "900",
                "--realtime",
                "--verbose",
            ],
            cwd=str(HEADLESS_EXE.parent),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=45,
        )
        print("=== GAME EXIT:", game.returncode, "===")
        for line in game.stdout.splitlines():
            if any(k in line for k in ("[mp]", "[MP-DBG]", "[NET]", "GLXPlayer", "ServerConfig", "LoadLevel", "Lobby", "state]", "loading")):
                print(line)
    finally:
        srv.terminate()
        srv_out, _ = srv.communicate(timeout=5)
        script_path.unlink(missing_ok=True)

    print("\n=== SERVER LOG ===")
    print(srv_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
