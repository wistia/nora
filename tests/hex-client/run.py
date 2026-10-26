#!/usr/bin/env python3
"""Opt-in public Hex + real Mix integration smoke; no project-global config changes."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
from upstream import Server, Handler

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=str(REPO / "target/debug/nora"))
    parser.add_argument("--skip-public", action="store_true")
    parser.add_argument("--hex-version", default="2.6.0")
    parser.add_argument("--s3", action="store_true", help="Run against an ephemeral local MinIO container (requires Docker and AWS CLI)")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    results = {}
    with tempfile.TemporaryDirectory(prefix="nora-hex-") as scratch:
        scratch = Path(scratch)
        base = {k: v for k, v in os.environ.items()
                if not k.startswith(("HEX_", "NORA_", "MIX_"))}
        base.update(HEX_UNSAFE_REGISTRY="0", HEX_NO_VERIFY_REPO_ORIGIN="0",
                    HEX_UNSAFE_HTTPS="0", HEX_COOLDOWN="0d", HEX_OFFLINE="0",
                    MIX_HOME=str(scratch / "mix"))
        # Bootstrap Hex before setting the package mirror; installation archives
        # are explicitly outside Nora's Hex protocol scope.
        for name in ("HEX_MIRROR", "HEX_TRUSTED_MIRROR"):
            base.pop(name, None)
        subprocess.run(["mix", "local.hex", args.hex_version, "--force"], env=base, check=True)
        processes = []
        logs = []
        minio = None
        s3_url = None
        buckets = set()
        def stop(proc):
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        def start(label, upstream, public_key=None, offline=False):
            area = scratch / label
            area.mkdir(exist_ok=True)
            port = free_port()
            config = area / "nora.toml"
            q = json.dumps
            storage = 'mode = "local"\n'
            if args.s3:
                bucket = "nora-hex-" + label
                if bucket not in buckets:
                    aws_env = base | {"AWS_ACCESS_KEY_ID": "norahex", "AWS_SECRET_ACCESS_KEY": "norahex-test-only", "AWS_DEFAULT_REGION": "us-east-1", "AWS_EC2_METADATA_DISABLED": "true"}
                    aws_env.pop("AWS_SESSION_TOKEN", None)
                    subprocess.run(["aws", "--endpoint-url", s3_url, "s3api", "create-bucket", "--bucket", bucket], env=aws_env, check=True)
                    buckets.add(bucket)
                storage = f'mode = "s3"\ns3_url = {q(s3_url)}\nbucket = {q(bucket)}\ns3_access_key = "norahex"\ns3_secret_key = "norahex-test-only"\n'
            config.write_text(f'''[server]
host = "127.0.0.1"
port = {port}
trust_upstream_dates = true
[registries]
enable = ["hex"]
[storage]
{storage}path = {q(str(area / "storage"))}
[auth]
enabled = true
anonymous_read = true
htpasswd_file = {q(str(area / "users"))}
token_storage = {q(str(area / "tokens"))}
[curation]
mode = "enforce"
min_release_age = "7d"
quarantine = "enforce"
quarantine_ttl = "7d"
[rate_limit]
enabled = false
[hex]
proxy = {q(upstream)}
metadata_ttl = 0
''' + (f'public_key_file = {q(str(public_key))}\n' if public_key else ""))
            (area / "users").touch()
            env = base | {"NORA_CONFIG_PATH": str(config)}
            if offline:
                env.update(HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9",
                           ALL_PROXY="http://127.0.0.1:9", NO_PROXY="127.0.0.1,localhost")
            log = open(area / "server.log", "w+")
            logs.append(log)
            proc = subprocess.Popen([binary, "serve"], env=env, stdout=log, stderr=subprocess.STDOUT)
            processes.append(proc)
            mirror = f"http://127.0.0.1:{port}/hex"
            for _ in range(100):
                if proc.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    urlopen(f"http://127.0.0.1:{port}/health", timeout=1).close()
                    return proc, mirror
                except (HTTPError, URLError, OSError):
                    time.sleep(.1)
            raise RuntimeError("Nora did not start")
        def app(label, mirror, key=None, cooldown="0d", locked=True, expected=True):
            area = scratch / (label + "-app")
            shutil.copytree(ROOT / "app", area, ignore=shutil.ignore_patterns("deps", "_build"))
            if not locked:
                (area / "mix.lock").unlink()
            env = base | {"HEX_HOME": str(scratch / (label + "-hex")),
                          "HEX_MIRROR": mirror, "HEX_COOLDOWN": cooldown}
            if key:
                subprocess.run(["mix", "hex.repo", "set", "hexpm", "--public-key", str(key)],
                               env=env, cwd=area, check=True)
            subprocess.run(["mix", "hex.config"], env=env, cwd=area, check=True)
            fetched = subprocess.run(["mix", "deps.get"], env=env, cwd=area,
                                     text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(fetched.stdout, flush=True)
            if expected:
                assert fetched.returncode == 0, fetched.stdout
                subprocess.run(["mix", "run", "-e", "NoraSmoke.run"], env=env, cwd=area, check=True)
            else:
                assert fetched.returncode != 0 and "403" in fetched.stdout, fetched.stdout
            results[label] = "passed"
        try:
            if args.s3:
                s3_port = free_port()
                s3_url = f"http://127.0.0.1:{s3_port}"
                minio = "nora-hex-smoke-" + str(os.getpid())
                subprocess.run(["docker", "run", "--rm", "-d", "--name", minio,
                    "-p", f"127.0.0.1:{s3_port}:9000", "-e", "MINIO_ROOT_USER=norahex",
                    "-e", "MINIO_ROOT_PASSWORD=norahex-test-only",
                    "quay.io/minio/minio:RELEASE.2025-02-07T23-21-09Z", "server", "/data"], check=True)
                for _ in range(100):
                    try:
                        urlopen(s3_url + "/minio/health/live", timeout=1).close()
                        break
                    except (HTTPError, URLError, OSError):
                        time.sleep(.1)
                else:
                    raise RuntimeError("MinIO did not start")
            if not args.skip_public:
                proc, mirror = start("public", "https://repo.hex.pm")
                app("public-cold", mirror, cooldown="7d")
                stop(proc)
                proc, mirror = start("public", "https://repo.hex.pm", offline=True)
                # Prove the network is blocked using an uncached package.
                try:
                    urlopen(mirror + "/packages/phoenix", timeout=10)
                    raise AssertionError("uncached request unexpectedly worked offline")
                except HTTPError as exc:
                    assert exc.code == 502
                app("public-offline", mirror, cooldown="7d")
                stop(proc)
            upstream = Server(("127.0.0.1", 0), Handler)
            threading.Thread(target=upstream.serve_forever, daemon=True).start()
            url = f"http://127.0.0.1:{upstream.server_port}"
            key = ROOT / "fixtures/test-public.pem"
            proc, mirror = start("young", url, key)
            app("young-locked", mirror, key, locked=True, expected=False)
            app("young-pinned", mirror, key, locked=False, expected=False)
            stop(proc)
            upstream.age_days = 8
            proc, mirror = start("mature", url, key)
            app("mature", mirror, key, cooldown="7d", locked=False)
            stop(proc)
            upstream.shutdown()
        finally:
            for proc in processes:
                stop(proc)
            for log in logs:
                log.close()
            if minio:
                subprocess.run(["docker", "rm", "-f", minio], check=False)
            output = ROOT / ".state"
            output.mkdir(exist_ok=True)
            for logfile in scratch.glob("*/server.log"):
                shutil.copy(logfile, output / (("s3-" if args.s3 else args.hex_version + "-") + logfile.parent.name + "-server.log"))
            (output / ("results-s3.json" if args.s3 else "results-" + args.hex_version + ".json")).write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
