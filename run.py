"""One-command local launcher for SentinelMesh (Windows/macOS/Linux)."""
import os, shutil, socket, subprocess, sys, time, threading
from pathlib import Path

ROOT=Path(__file__).resolve().parent
VENV=ROOT/".venv"
PYTHON=VENV/("Scripts/python.exe" if os.name=="nt" else "bin/python")
NPM="npm.cmd" if os.name=="nt" else "npm"

def run_setup(command):
    result=subprocess.run(command,cwd=ROOT)
    if result.returncode: raise SystemExit(result.returncode)

def relay(proc,label):
    for line in iter(proc.stdout.readline,""):
        print(f"[{label}] {line}",end="",flush=True)

def main():
    if not PYTHON.exists():
        print("[setup] Creating local Python environment…",flush=True)
        run_setup([sys.executable,"-m","venv",str(VENV)])
    marker=VENV/".sentinelmesh-deps"
    if not marker.exists():
        print("[setup] Installing backend dependencies…",flush=True)
        run_setup([str(PYTHON),"-m","pip","install","-r",str(ROOT/"backend"/"requirements.txt")])
        marker.write_text("installed",encoding="utf-8")
    if not (ROOT/"node_modules"/"vite").exists():
        print("[setup] Installing frontend dependencies…",flush=True)
        run_setup([NPM,"install","--cache",str(ROOT/".npm-cache")])
    procs=[]
    try:
        api_port=8000
        while api_port<8100:
            with socket.socket() as sock:
                try:
                    sock.bind(("127.0.0.1",api_port))
                    break
                except OSError:
                    api_port+=1
        if api_port>=8100:raise RuntimeError("No free local API port found in the 8000–8099 range.")
        backend=subprocess.Popen([str(PYTHON),"-m","uvicorn","backend.main:app","--host","127.0.0.1","--port",str(api_port)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        procs.append(backend)
        # Vite proxies /api (including EventSource) to the exact API port
        # selected above; the browser never needs to assume port 8000.
        frontend_env={**os.environ,"SENTINELMESH_API_PORT":str(api_port)}
        frontend=subprocess.Popen([NPM,"run","dev","--","--host","127.0.0.1"],cwd=ROOT,env=frontend_env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        procs.append(frontend)
        for p,name in zip(procs,("api","web")): threading.Thread(target=relay,args=(p,name),daemon=True).start()
        print(f"\nSentinelMesh is starting. UI: http://127.0.0.1:5173  API docs: http://127.0.0.1:{api_port}/docs\nPress Ctrl+C to stop both services.\n",flush=True)
        while True:
            for p in procs:
                code=p.poll()
                if code is not None: raise RuntimeError(f"A SentinelMesh service exited with status {code}.")
            time.sleep(.5)
    except KeyboardInterrupt:
        print("\nStopping SentinelMesh…",flush=True)
    finally:
        for p in procs:
            if p.poll() is None:p.terminate()
        for p in procs:
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill()

if __name__=="__main__": main()
