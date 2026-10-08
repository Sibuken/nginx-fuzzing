#!/usr/bin/env python3

import argparse
import concurrent.futures
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "fuzz/docker/docker-compose.yml"
TARGETS = [
    "NGX-OSS-HTTP", "NGX-IF06", "NGX-IF07",
    "NGX-IF08", "NGX-IF09", "NGX-IF10", "NGX-IF11", "NGX-IF12",
    "NGX-IF13", "NGX-IF14", "NGX-IF15", "NGX-IF16", "NGX-IF17",
    "NGX-IF18", "NGX-IF19", "NGX-IF20", "NGX-IF21",
]


def target_result_label(result):
    status = result.get("status", "missing_manifest")
    exit_code = result.get("process_exit_code", 1)
    expected_exit = exit_code == 0 or (status == "finding" and exit_code == 77)
    if not expected_exit:
        return f"orchestration_error (exit {result['process_exit_code']})"
    if status == "finding":
        return f"finding (stop_reason={result.get('stop_reason', 'unknown')})"
    if status == "passed":
        return "passed"
    return f"{status} (stop_reason={result.get('stop_reason', 'unknown')})"


def target_result_completed(result):
    status = result.get("status")
    exit_code = result.get("process_exit_code")
    return status in ("passed", "finding") and (
        exit_code == 0 or (status == "finding" and exit_code == 77)
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run nginx fuzz campaigns concurrently using one prebuilt image."
    )
    parser.add_argument("targets", nargs="*", choices=TARGETS,
                        help="targets to run (default: all configured targets)")
    parser.add_argument("--jobs", type=int,
                        default=int(os.environ.get("FUZZ_PARALLEL_JOBS", "4")),
                        help="maximum concurrent campaigns (default: 4)")
    parser.add_argument("--project-prefix", default="nginx-fuzz",
                        help="prefix for isolated Compose project names")
    parser.add_argument("--network", default=os.environ.get("FUZZ_DOCKER_NETWORK", "nginx-fuzz-shared"),
                        help="shared external Docker network (created once if absent)")
    parser.add_argument("--plateau-seconds", type=int, default=7200)
    parser.add_argument("--coverage-check-interval-seconds", type=int, default=300)
    parser.add_argument("--max-seconds", type=int, default=0)
    parser.add_argument("--max-len", type=int, default=65536)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--rss-limit-mb", type=int, default=2048)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--reuse-corpus", action="append", default=[])
    args = parser.parse_args()
    if not args.targets:
        args.targets = TARGETS
    if len(set(args.targets)) != len(args.targets):
        parser.error("target names must be unique")
    if args.jobs < 1:
        parser.error("--jobs must be at least 1")
    if args.plateau_seconds < 1 or args.coverage_check_interval_seconds < 1:
        parser.error("plateau and coverage-check intervals must be positive")
    if args.max_seconds < 0:
        parser.error("--max-seconds cannot be negative")
    return args


def run_target(args, target, image, image_id, group_id, project_prefix, runs_dir):
    project_name = f"{project_prefix}-{target.lower()}-{group_id}"
    command = [
        "docker", "compose",
        "--project-directory", str(ROOT),
        "--file", str(COMPOSE_FILE),
        "--project-name", project_name,
        "run", "--rm", "--no-deps", "--pull", "never", "--no-TTY",
        "nginx-fuzz", "campaign", target,
        "--plateau-seconds", str(args.plateau_seconds),
        "--coverage-check-interval-seconds", str(args.coverage_check_interval_seconds),
        "--max-len", str(args.max_len),
        "--timeout", str(args.timeout),
        "--rss-limit-mb", str(args.rss_limit_mb),
        "--seed", str(args.seed),
    ]
    if args.max_seconds:
        command.extend(["--max-seconds", str(args.max_seconds)])
    for corpus in args.reuse_corpus:
        command.extend(["--reuse-corpus", corpus])

    env = os.environ.copy()
    env.update({
        "FUZZ_IMAGE": image,
        "FUZZ_IMAGE_ID": image_id,
        "FUZZ_RUNS_DIR": str(runs_dir),
        "FUZZ_DOCKER_NETWORK": args.network,
    })
    print(f"[{target}] compose project {project_name}: starting", flush=True)
    process = subprocess.Popen(
        command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, errors="replace", bufsize=1,
    )
    assert process.stdout is not None
    run_id = None
    for line in process.stdout:
        print(f"[{target}] {line}", end="", flush=True)
        match = re.search(r"run directory: /runs/([^/\s]+)/([^/\s]+)", line)
        if match and match.group(1) == target:
            run_id = match.group(2)
    process_exit_code = process.wait()
    result = {
        "target": target,
        "process_exit_code": process_exit_code,
        "run_id": run_id,
        "status": "missing_manifest",
        "stop_reason": None,
    }
    if run_id is not None:
        manifest_path = runs_dir / target / run_id / "manifest.json"
        try:
            with open(manifest_path, encoding="utf-8") as stream:
                manifest = json.load(stream)
            result["status"] = manifest.get("status", "missing_status")
            result["stop_reason"] = manifest.get("stop_reason")
        except (OSError, json.JSONDecodeError) as error:
            result["manifest_error"] = str(error)
    return result


def main():
    args = parse_args()
    image = os.environ.get("FUZZ_IMAGE", "nginx-fuzz:1.30.5")
    runs_dir = pathlib.Path(os.environ.get("FUZZ_RUNS_DIR", ROOT / "fuzz/runs")).resolve()
    runs_dir.mkdir(parents=True, exist_ok=True)
    prefix = re.sub(r"[^a-z0-9_-]+", "-", args.project_prefix.lower()).strip("-_")[:24]
    if not prefix:
        print("error: --project-prefix must contain a Docker-safe character", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.network):
        print("error: --network must be a valid Docker network name", file=sys.stderr)
        return 2

    network_check = subprocess.run(
        ["docker", "network", "inspect", "--format", "{{.Id}}", args.network],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if network_check.returncode != 0:
        created = subprocess.run(
            ["docker", "network", "create", args.network],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if created.returncode != 0:
            # Another campaign invocation may have created it concurrently.
            network_check = subprocess.run(
                ["docker", "network", "inspect", "--format", "{{.Id}}", args.network],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            if network_check.returncode != 0:
                print(f"error: could not create shared Docker network {args.network!r}: {created.stderr.strip()}",
                      file=sys.stderr)
                return 2
        else:
            print(f"Created shared Docker network {args.network}", flush=True)

    inspected = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if inspected.returncode != 0:
        print(f"error: image {image!r} is not available locally; build it once with ./fuzz/scripts/fuzz.sh build",
              file=sys.stderr)
        return 2

    group_id = uuid.uuid4().hex[:8]
    started = time.monotonic()
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {
            executor.submit(
                run_target, args, target, image, inspected.stdout.strip(),
                group_id, prefix, runs_dir,
            ): target
            for target in args.targets
        }
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                results[target] = future.result()
            except Exception as error:
                print(f"[{target}] orchestration error: {error}", file=sys.stderr)
                results[target] = {
                    "target": target,
                    "process_exit_code": 1,
                    "status": "orchestration_error",
                    "stop_reason": None,
                    "error": str(error),
                }

    print("\nCampaign summary:")
    for target in args.targets:
        result = results.get(target, {"process_exit_code": 1, "status": "missing_result"})
        run_id = f" [run {result['run_id']}]" if result.get("run_id") else ""
        print(f"  {target}: {target_result_label(result)}{run_id}")
    print(f"Elapsed: {time.monotonic() - started:.1f}s; targets: {len(args.targets)}; workers: {args.jobs}")
    return 0 if all(target_result_completed(result) for result in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
