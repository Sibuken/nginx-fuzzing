#!/usr/bin/env python3

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import pathlib
import platform
import queue
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid


ROOT = pathlib.Path("/opt/fuzz")
RUNS = pathlib.Path(os.environ.get("FUZZ_RUNS_DIR", "/runs"))
DEFAULT_TARGET = "NGX-OSS-HTTP"
TARGET = DEFAULT_TARGET
BIN_NAME = "http_request_fuzzer"
FUZZ_BIN = ROOT / "bin/fuzz" / BIN_NAME
COVERAGE_BIN = ROOT / "bin/coverage" / BIN_NAME
SEEDS = ROOT / "seeds" / TARGET
DICTIONARY = ROOT / "dict" / f"{TARGET}.dict"
PROTO = ROOT / "bin/fuzz/http_request_proto.proto"
PROTOC = pathlib.Path("/opt/lpm-build/external.protobuf/bin/protoc")
LLVM_PROFDATA = "llvm-profdata-14"
LLVM_COV = "llvm-cov-14"
CHILD = None
STOP_SIGNAL = None


def activate_target(target):
    global TARGET, BIN_NAME, FUZZ_BIN, COVERAGE_BIN, SEEDS, DICTIONARY, PROTO
    config_path = ROOT / f"targets/{target}/target.json"
    if not config_path.is_file():
        raise SystemExit(f"unknown target: {target}")
    with open(config_path, encoding="utf-8") as stream:
        config = json.load(stream)
    TARGET = target
    BIN_NAME = config.get("binary", "http_request_fuzzer")
    FUZZ_BIN = ROOT / "bin/fuzz" / BIN_NAME
    COVERAGE_BIN = ROOT / "bin/coverage" / BIN_NAME
    SEEDS = ROOT / "seeds" / TARGET
    DICTIONARY = ROOT / "dict" / f"{TARGET}.dict"
    PROTO = ROOT / "bin/fuzz/http_request_proto.proto"


def utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_inventory(directory):
    return [
        {"name": str(path.relative_to(directory)), "sha256": sha256(path), "size": path.stat().st_size}
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    ]


def target_config():
    with open(ROOT / f"targets/{TARGET}/target.json", encoding="utf-8") as stream:
        return json.load(stream)


def new_run_id(kind):
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{kind}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary, path)


def prepare_run(kind, run_id=None):
    run_id = run_id or new_run_id(kind)
    run_dir = RUNS / TARGET / run_id
    for relative in (
        "logs", "corpus_in", "corpus_out", "artifacts",
        "defects", "coverage/baseline", "coverage/final"
    ):
        (run_dir / relative).mkdir(parents=True, exist_ok=False)

    for seed in sorted(SEEDS.iterdir()):
        if seed.is_file():
            shutil.copy2(seed, run_dir / "corpus_in" / seed.name)
    shutil.copy2(DICTIONARY, run_dir / "dictionary.dict")
    shutil.copy2(ROOT / "upstream.lock.json", run_dir / "upstream.lock.json")
    shutil.copy2(ROOT / f"targets/{TARGET}/target.json", run_dir / "target.json")
    return run_id, run_dir


def command_versions():
    return (ROOT / "toolchain.txt").read_text(encoding="utf-8").strip().splitlines()


def base_manifest(kind, run_id, run_dir, args):
    config = target_config()
    lock = json.loads((ROOT / "upstream.lock.json").read_text(encoding="utf-8"))
    return {
        "schema_version": 1,
        "run_id": run_id,
        "kind": kind,
        "target": TARGET,
        "upstream_target": config.get("upstream_target"),
        "started_at_utc": utc_now(),
        "finished_at_utc": None,
        "status": "running",
        "stop_reason": None,
        "exit_code": None,
        "signal": None,
        "duration_seconds": None,
        "nginx": {
            "version": (ROOT / "nginx-version.txt").read_text(encoding="utf-8").strip(),
            "revision": (ROOT / "nginx-revision.txt").read_text(encoding="utf-8").strip(),
            "source_sha256": (ROOT / "nginx-source.sha256").read_text(encoding="utf-8").strip()
        },
        "environment": {
            "container_architecture": platform.machine(),
            "host_architecture": (ROOT / "host-architecture.txt").read_text(encoding="utf-8").strip(),
            "platform": "linux/amd64",
            "emulated": platform.machine() in ("x86_64", "amd64") and (ROOT / "host-architecture.txt").read_text(encoding="utf-8").strip() == "arm64",
            "toolchain": command_versions(),
            "allocator_mode": config["allocator_mode"],
            "image_reference": os.environ.get("FUZZ_IMAGE_REFERENCE", "nginx-fuzz:1.30.5"),
            "image_id": os.environ.get("FUZZ_IMAGE_ID", "not supplied by container runtime")
        },
        "limits": {
            "seconds": getattr(args, "seconds", None),
            "max_seconds": getattr(args, "max_seconds", None),
            "coverage_check_interval_seconds": getattr(args, "coverage_check_interval_seconds", None),
            "max_len": args.max_len,
            "timeout_seconds": args.timeout,
            "rss_limit_mb": args.rss_limit_mb,
            "random_seed": args.seed,
            "single_process": kind != "campaign",
            "fuzzer_mode": "fork" if kind == "campaign" else "in_process"
        },
        "scope": config["scopes"],
        "stop_policy": {
            "stop_on_first_finding": kind != "campaign",
            "continue_after_finding": kind == "campaign",
            "fuzzer_fork_mode": kind == "campaign",
            "ignore_crashes": kind == "campaign",
            "stop_on_coverage": kind == "campaign",
            "plateau_seconds": getattr(args, "plateau_seconds", None),
            "coverage_metric": "cumulative LLVM scope lines and branches",
            "scope_threshold_percent": 90
        },
        "build": {
            "fuzz_compile_flags": (ROOT / "bin/fuzz/compile-flags.txt").read_text(encoding="utf-8").strip(),
            "fuzz_link_flags": (ROOT / "bin/fuzz/link-flags.txt").read_text(encoding="utf-8").strip(),
            "coverage_compile_flags": (ROOT / "bin/coverage/compile-flags.txt").read_text(encoding="utf-8").strip(),
            "coverage_link_flags": (ROOT / "bin/coverage/link-flags.txt").read_text(encoding="utf-8").strip(),
            "fuzz_binary_sha256": sha256(FUZZ_BIN),
            "coverage_binary_sha256": sha256(COVERAGE_BIN)
        },
        "adapter": {
            "origin": config["origin"],
            "input_format": config["input_format"],
            "mutator": config["mutator"],
            "configuration_profile": config["configuration_profile"],
            "state": config["state"],
            "known_limitations": config["known_limitations"]
        },
        "upstream": lock,
        "corpus_in": file_inventory(run_dir / "corpus_in"),
        "dictionary": {"sha256": sha256(run_dir / "dictionary.dict"), "path": "dictionary.dict"},
        "patches": file_inventory(ROOT / "patches"),
        "command": None,
        "coverage": {},
        "coverage_threshold_met": None,
        "findings": []
    }


def signal_handler(signum, _frame):
    global CHILD, STOP_SIGNAL
    STOP_SIGNAL = signum
    if CHILD is not None and CHILD.poll() is None:
        try:
            os.killpg(CHILD.pid, signum)
        except ProcessLookupError:
            pass


def elapsed_hms(seconds):
    total_seconds = max(0, int(seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def campaign_log_event(path, context, message):
    now = time.monotonic()
    elapsed = now - context["started"]
    idle = max(0.0, now - context["last_growth"])
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    line = (
        f"[{timestamp}] elapsed={elapsed_hms(elapsed)} "
        f"no_coverage_growth={elapsed_hms(idle)} {message}"
    )
    print(line, flush=True)
    with open(path, "a", encoding="utf-8") as log:
        log.write(line + "\n")
        log.flush()


def run_logged(command, log_path, env=None, campaign_log_path=None, campaign_context=None):
    global CHILD
    started = time.monotonic()
    with open(log_path, "a" if log_path.exists() else "w", encoding="utf-8", errors="replace") as log:
        log.write("command: " + " ".join(str(item) for item in command) + "\n")
        log.flush()
        CHILD = subprocess.Popen(
            [str(item) for item in command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            env=env,
            start_new_session=True,
        )
        assert CHILD.stdout is not None
        if campaign_log_path is None or campaign_context is None:
            for line in CHILD.stdout:
                sys.stdout.write(line)
                log.write(line)
        else:
            output_queue = queue.Queue()

            def read_child_output():
                for output_line in CHILD.stdout:
                    output_queue.put(output_line)
                output_queue.put(None)

            output_thread = threading.Thread(target=read_child_output, daemon=True)
            output_thread.start()
            while True:
                try:
                    output_line = output_queue.get(timeout=60)
                except queue.Empty:
                    campaign_log_event(
                        campaign_log_path,
                        campaign_context,
                        "watchdog event=heartbeat "
                        f"round={campaign_context['round']} "
                        f"round_elapsed={elapsed_hms(time.monotonic() - campaign_context['round_started'])} "
                        f"idle_seconds={time.monotonic() - campaign_context['last_growth']:.1f} "
                        f"required_seconds={campaign_context['plateau_seconds']} "
                        f"scope_lines={campaign_context['scope_lines']}",
                    )
                    continue
                if output_line is None:
                    break
                now = time.monotonic()
                timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                prefix = (
                    f"[{timestamp}] elapsed={elapsed_hms(now - campaign_context['started'])} "
                    f"round_elapsed={elapsed_hms(now - campaign_context['round_started'])} "
                )
                output_line = prefix + output_line
                sys.stdout.write(output_line)
                sys.stdout.flush()
                log.write(output_line)
                log.flush()
                with open(campaign_log_path, "a", encoding="utf-8") as campaign_log:
                    campaign_log.write(output_line)
                    campaign_log.flush()
            output_thread.join()
        code = CHILD.wait()
        CHILD = None
    return code, time.monotonic() - started


def run_campaign_logged(command, log_path, check_interval, check_callback):
    """Run libFuzzer while periodically sampling retained-corpus coverage."""
    global CHILD
    started = time.monotonic()
    callback_error = []
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        log.write("command: " + " ".join(str(item) for item in command) + "\n")
        log.flush()
        CHILD = subprocess.Popen(
            [str(item) for item in command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            start_new_session=True,
        )

        def copy_output():
            assert CHILD is not None and CHILD.stdout is not None
            for line in CHILD.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                log.write(line)
                log.flush()

        output_thread = threading.Thread(target=copy_output, daemon=True)
        output_thread.start()
        next_check = time.monotonic() + check_interval
        try:
            while CHILD.poll() is None:
                now = time.monotonic()
                if now >= next_check:
                    try:
                        check_callback(now - started)
                    except Exception as error:
                        callback_error.append(error)
                        os.killpg(CHILD.pid, signal.SIGTERM)
                        break
                    next_check = time.monotonic() + check_interval
                time.sleep(min(1.0, max(0.05, next_check - time.monotonic())))
            code = CHILD.wait()
        finally:
            output_thread.join()
            CHILD = None
    if callback_error:
        raise RuntimeError(f"campaign coverage observer failed: {callback_error[0]}")
    return code, time.monotonic() - started


def classify_artifacts(run_dir, already_classified=None):
    already_classified = already_classified or set()
    findings = []
    for path in sorted((run_dir / "artifacts").glob("*")):
        if not path.is_file() or path.name in already_classified:
            continue
        destination = run_dir / "defects" / path.name
        shutil.copy2(path, destination)
        finding = {
            "input": str(path.relative_to(run_dir)),
            "sha256": sha256(path),
            "size": path.stat().st_size,
            "status": "needs_analysis",
            "symptom": path.name.split("-", 1)[0],
            "evidence": f"defects/{path.name}.sanitizer.log",
            "reproduce": f"docker run --rm --platform linux/amd64 -v $PWD/fuzz/runs:/runs nginx-fuzz:1.30.5 reproduce {TARGET} /runs/{TARGET}/{run_dir.name}/artifacts/{path.name}"
        }
        for mode, binary in (("sanitizer", FUZZ_BIN), ("without_sanitizers", COVERAGE_BIN)):
            replay_log = run_dir / "defects" / f"{path.name}.{mode}.log"
            with open(replay_log, "w", encoding="utf-8", errors="replace") as stream:
                completed = subprocess.run(
                    [str(binary), "-runs=1", str(path)],
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            finding[f"{mode}_replay"] = {
                "exit_code": completed.returncode,
                "log": str(replay_log.relative_to(run_dir))
            }
        findings.append(finding)
    return findings


def finding_stop_reason(findings):
    symptoms = {finding["symptom"] for finding in findings}
    if "timeout" in symptoms:
        return "timeout"
    if "oom" in symptoms:
        return "oom"
    if "slow" in symptoms:
        return "slow"
    return "crash"


def campaign_resilience_flags():
    # libFuzzer 14 ignores crashes only under its fork supervisor mode.
    return ["-fork=1", "-ignore_crashes=1"]


def expected_fork_exit(code, findings, log_text=""):
    # Fork mode may return the last worker's bug exit code after saving its artifact.
    if code == 0 or (code in (70, 71, 77) and bool(findings)):
        return True

    # LLVM 14's fork supervisor returns the *last worker's* exit code even when
    # -ignore_crashes=1 is set. Accept a non-zero result only when the log proves
    # that the supervisor reached its configured time limit and printed its
    # final exit line; otherwise keep treating it as an infrastructure failure.
    return (
        "INFO: fuzzed for " in log_text
        and "wrapping up soon" in log_text
        and re.search(rf"INFO: exiting: {code} time: \d+s", log_text) is not None
    )


def read_run_log(path):
    path = pathlib.Path(path)
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    compressed = path.with_name(path.name + ".gz")
    if compressed.is_file():
        with gzip.open(compressed, "rt", encoding="utf-8", errors="replace") as stream:
            return stream.read()
    return ""


def fork_worker_counters(log_text):
    matches = re.findall(
        r"oom/timeout/crash:\s*(\d+)/(\d+)/(\d+)", log_text
    )
    if not matches:
        return None
    oom, timeouts, crashes = (int(value) for value in matches[-1])
    return {"oom": oom, "timeouts": timeouts, "crashes": crashes}


def parse_lcov(path):
    records = {}
    current = None
    with open(path, encoding="utf-8") as stream:
        for raw_line in stream:
            line = raw_line.rstrip("\n")
            if line.startswith("SF:"):
                current = line[3:]
                records.setdefault(current, {"lines": {}, "branches": {}})
            elif current is not None and line.startswith("DA:"):
                number, count, *_ = line[3:].split(",")
                records[current]["lines"][int(number)] = int(count)
            elif current is not None and line.startswith("BRDA:"):
                number, block, branch, taken = line[5:].split(",")
                records[current]["branches"][(int(number), block, branch)] = (
                    0 if taken == "-" else int(taken)
                )
            elif line == "end_of_record":
                current = None
    return records


def function_ranges(function, suffix):
    ranges = []
    filenames = function.get("filenames", [])
    # The first kind-0 region for the defining file is the function body.
    # Unlike nested regions, it is used only as a range filter; executable and
    # covered lines themselves come from llvm-cov's LCOV DA records.
    for region in function.get("regions", []):
        if len(region) < 8 or region[7] != 0:
            continue
        file_id = region[5]
        if file_id < len(filenames) and filenames[file_id].endswith(suffix):
            ranges.append((region[0], region[2]))
            break
    return ranges


def summarize_coverage(export_path, lcov_path):
    with open(export_path, encoding="utf-8") as stream:
        document = json.load(stream)
    functions = {}
    for unit in document.get("data", []):
        for function in unit.get("functions", []):
            functions.setdefault(function["name"], []).append(function)

    lcov = parse_lcov(lcov_path)
    scopes = []
    for scope in target_config()["scopes"]:
        ranges = []
        found = []
        for name in scope["functions"]:
            # llvm-cov prefixes internal-linkage C functions with
            # "<translation-unit>:".  Target metadata deliberately keeps the
            # source-level function name, so accept either spelling here.
            matches = functions.get(name, [])
            if not matches:
                matches = [
                    function
                    for symbol, entries in functions.items()
                    if symbol.endswith(f":{name}")
                    for function in entries
                ]
            for function in matches:
                ranges.extend(function_ranges(function, scope["file"]))
            if matches:
                found.append(name)
        all_lines = set()
        hit_lines = set()
        all_branches = set()
        hit_branches = set()
        for filename, record in lcov.items():
            if not filename.endswith(scope["file"]):
                continue
            for number, count in record["lines"].items():
                if any(start <= number <= end for start, end in ranges):
                    all_lines.add((filename, number))
                    if count > 0:
                        hit_lines.add((filename, number))
            for identity, count in record["branches"].items():
                number = identity[0]
                if any(start <= number <= end for start, end in ranges):
                    key = (filename, *identity)
                    all_branches.add(key)
                    if count > 0:
                        hit_branches.add(key)
        scopes.append({
            "id": scope["id"],
            "file": scope["file"],
            "functions": scope["functions"],
            "functions_found": found,
            "lines": {
                "covered": len(hit_lines),
                "total": len(all_lines),
                "percent": round(100.0 * len(hit_lines) / len(all_lines), 2) if all_lines else None,
                "covered_line_ids": [f"{path}:{line}" for path, line in sorted(hit_lines)]
            },
            "branches": {
                "covered": len(hit_branches),
                "total": len(all_branches),
                "percent": round(100.0 * len(hit_branches) / len(all_branches), 2) if all_branches else None
            }
        })
    totals = document.get("data", [{}])[0].get("totals", {})
    nginx_lines = {}
    nginx_branches = {}
    for filename, record in lcov.items():
        if "/work/nginx-coverage/src/" not in filename:
            continue
        nginx_lines.update({(filename, line): count for line, count in record["lines"].items()})
        nginx_branches.update({(filename, *key): count for key, count in record["branches"].items()})
    nginx_summary = {
        "lines": {
            "covered": sum(count > 0 for count in nginx_lines.values()),
            "total": len(nginx_lines),
        },
        "branches": {
            "covered": sum(count > 0 for count in nginx_branches.values()),
            "total": len(nginx_branches),
        },
    }
    for metric in nginx_summary.values():
        metric["percent"] = round(100.0 * metric["covered"] / metric["total"], 2) if metric["total"] else None
    return {"whole_instrumented_build": totals, "nginx_source": nginx_summary, "scopes": scopes}


def merge_coverage_profiles(base_profile, raw_profiles, merged):
    merge_inputs = ([base_profile] if base_profile is not None else []) + raw_profiles
    if base_profile is not None and not raw_profiles:
        shutil.copy2(base_profile, merged)
    else:
        subprocess.run([LLVM_PROFDATA, "merge", "-sparse", *map(str, merge_inputs), "-o", str(merged)], check=True)


def compact_coverage_summary(summary):
    """Keep report metrics, but omit per-line IDs that dominate JSON size."""
    result = {
        key: summary[key]
        for key in ("label", "inputs", "duration_seconds", "nginx_source", "whole_instrumented_build")
        if key in summary
    }
    result["scopes"] = []
    for scope in summary.get("scopes", []):
        compact_scope = {key: scope[key] for key in ("id", "file", "functions") if key in scope}
        for metric in ("lines", "branches"):
            if metric in scope:
                compact_scope[metric] = {
                    key: scope[metric][key]
                    for key in ("covered", "total", "percent")
                    if key in scope[metric]
                }
        result["scopes"].append(compact_scope)
    return result


def compact_run_log(path):
    path = pathlib.Path(path)
    if not path.is_file() or path.suffix == ".gz":
        return
    compressed = path.with_name(path.name + ".gz")
    temporary = compressed.with_name(compressed.name + ".tmp")
    with open(path, "rb") as source, gzip.open(temporary, "wb", compresslevel=6) as output:
        shutil.copyfileobj(source, output)
    os.replace(temporary, compressed)
    path.unlink()


def compact_campaign_round_logs(logs_dir):
    """Compress per-round logs but leave the campaign timeline readable."""
    for log_path in pathlib.Path(logs_dir).glob("*.log"):
        if log_path.name != "campaign.log":
            compact_run_log(log_path)


def corpus_directory_stats(directory):
    root = pathlib.Path(directory)
    files = [path for path in root.rglob("*") if path.is_file()] if root.is_dir() else []
    return {"files": len(files), "bytes": sum(path.stat().st_size for path in files)}


def summarize_run_corpora(run_dir):
    """Record corpus size without changing or relocating the corpus files."""
    run_dir = pathlib.Path(run_dir)
    corpus_dirs = [run_dir / name for name in ("corpus_in", "corpus_out")]
    stats = {directory.name: corpus_directory_stats(directory) for directory in corpus_dirs}
    return stats


def copy_reuse_corpus(source, destination):
    """Copy a corpus directory or a corpus.tar.gz archive into corpus_in."""
    source = pathlib.Path(source)
    destination = pathlib.Path(destination)
    if source.is_dir():
        members = ((path.name, path.open("rb")) for path in sorted(source.rglob("*")) if path.is_file())
        for _, stream in members:
            with stream:
                temporary = destination / f".reuse-{uuid.uuid4().hex}"
                with open(temporary, "wb") as output:
                    shutil.copyfileobj(stream, output)
                digest = sha256(temporary)
                final = destination / digest
                if final.exists():
                    temporary.unlink()
                else:
                    os.replace(temporary, final)
        return
    if not source.is_file() or not tarfile.is_tarfile(source):
        raise SystemExit(f"reuse corpus does not exist or is not a directory/archive: {source}")
    with tarfile.open(source, "r:gz") as archive:
        for member in archive:
            member_path = pathlib.PurePosixPath(member.name)
            if not member.isfile():
                continue
            if member_path.is_absolute() or ".." in member_path.parts:
                raise SystemExit(f"unsafe path in reuse corpus archive: {member.name}")
            if member_path.parts and member_path.parts[0] not in ("corpus_in", "corpus_out"):
                continue
            stream = archive.extractfile(member)
            if stream is None:
                continue
            temporary = destination / f".reuse-{uuid.uuid4().hex}"
            with stream, open(temporary, "wb") as output:
                shutil.copyfileobj(stream, output)
            digest = sha256(temporary)
            final = destination / digest
            if final.exists():
                temporary.unlink()
            else:
                os.replace(temporary, final)


def materialize_run_corpus(run_dir, destination):
    """Return a readable corpus directory, restoring a compact archive if needed."""
    run_dir = pathlib.Path(run_dir)
    input_dir = run_dir / "corpus_in"
    output_dir = run_dir / "corpus_out"
    if input_dir.is_dir() and output_dir.is_dir():
        return [input_dir, output_dir]
    archive = run_dir / "corpus.tar.gz"
    if not archive.is_file():
        raise SystemExit(f"run has no retained corpus: {run_dir}")
    destination = pathlib.Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    copy_reuse_corpus(archive, destination)
    return [destination]


def run_coverage(corpus_dirs, output_dir, label, input_paths=None,
                 base_profile=None, generate_html=True, retain_exports=True):
    profiles = output_dir / "profiles"
    profiles.mkdir(parents=True, exist_ok=True)
    inputs = []
    seen = set()
    candidates = input_paths
    if candidates is None:
        candidates = []
        for corpus_dir in corpus_dirs:
            candidates.extend(sorted(corpus_dir.iterdir()))
    for path in candidates:
        if path.is_file():
            digest = sha256(path)
            if digest not in seen:
                seen.add(digest)
                inputs.append(path)

    log_path = output_dir / "replay.log"
    started = time.monotonic()
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        for index, input_path in enumerate(inputs):
            env = os.environ.copy()
            env["LLVM_PROFILE_FILE"] = str(profiles / f"{index}-%p.profraw")
            completed = subprocess.run(
                [str(COVERAGE_BIN), "-runs=1", str(input_path)],
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )
            if completed.returncode != 0:
                raise RuntimeError(f"coverage replay failed for {input_path}: {completed.returncode}")

    raw_profiles = sorted(profiles.glob("*.profraw"))
    if not raw_profiles and base_profile is None:
        raise RuntimeError("coverage replay produced no raw profiles")
    merged = output_dir / "merged.profdata"
    merge_coverage_profiles(base_profile, raw_profiles, merged)
    for raw_profile in raw_profiles:
        raw_profile.unlink(missing_ok=True)
    export_path = output_dir / "coverage.json"
    with open(export_path, "w", encoding="utf-8") as stream:
        subprocess.run([LLVM_COV, "export", str(COVERAGE_BIN), f"-instr-profile={merged}"], stdout=stream, check=True, text=True)
    lcov_path = output_dir / "coverage.lcov"
    with open(lcov_path, "w", encoding="utf-8") as stream:
        subprocess.run([
            LLVM_COV, "export", str(COVERAGE_BIN), f"-instr-profile={merged}",
            "-format=lcov"
        ], stdout=stream, check=True, text=True)
    with open(output_dir / "coverage.txt", "w", encoding="utf-8") as stream:
        subprocess.run([LLVM_COV, "report", str(COVERAGE_BIN), f"-instr-profile={merged}"], stdout=stream, check=True, text=True)
    if generate_html:
        html = output_dir / "html"
        subprocess.run([
            LLVM_COV, "show", str(COVERAGE_BIN), f"-instr-profile={merged}",
            "-format=html", f"-output-dir={html}", "-show-line-counts-or-regions",
            "-show-branches=count"
        ], check=True)
    summary = summarize_coverage(export_path, lcov_path)
    summary.update({"label": label, "inputs": len(inputs), "duration_seconds": round(time.monotonic() - started, 3)})
    atomic_json(output_dir / "summary.json", summary if retain_exports else compact_coverage_summary(summary))
    if not retain_exports:
        export_path.unlink(missing_ok=True)
        lcov_path.unlink(missing_ok=True)
        (output_dir / "replay.log").unlink(missing_ok=True)
        shutil.rmtree(output_dir / "html", ignore_errors=True)
    return summary


def write_report(run_dir, manifest):
    final = manifest.get("coverage", {}).get("final", {})
    findings = manifest.get("findings", [])
    pending_findings = count_findings_requiring_analysis(findings)
    lines = [
        f"# {TARGET} run {manifest['run_id']}", "",
        f"- Status: `{manifest['status']}`",
        f"- Stop reason: `{manifest['stop_reason']}`",
        f"- Exit code: `{manifest['exit_code']}`",
        f"- Duration: `{manifest['duration_seconds']}` seconds",
        f"- Findings requiring analysis: `{pending_findings}`", ""
    ]
    if manifest["kind"] == "campaign":
        policy = manifest["stop_policy"]
        lines.insert(5, f"- Coverage plateau window: `{policy['plateau_seconds']}` seconds")
        lines.insert(6, f"- Coverage checkpoints: `{len(manifest.get('coverage_checkpoints', []))}`")
    regression_check = manifest.get("regression_check")
    if regression_check is not None:
        cases = regression_check.get("cases", [])
        reproduced = sum(case.get("expected_sanitizer_diagnostic", False) for case in cases)
        summary = f"{reproduced}/{len(cases)} reproduced" if cases else "no fixtures"
        insertion_index = 7 if manifest["kind"] == "campaign" else 6
        lines.insert(insertion_index, f"- Regression preflight: `{summary}`")
    if findings:
        lines.extend([
            "## Finding replay results", "",
            "Exit code 0 means the reported symptom did not reproduce during replay; "
            "nonzero exits need log inspection and are not automatically confirmed.", "",
            "| Input | Observed symptom | Sanitizer replay | Without sanitizers | Review |",
            "| --- | --- | --- | --- | --- |",
        ])
        for finding in findings:
            input_name = pathlib.Path(finding["input"]).name
            sanitizer = replay_summary(finding.get("sanitizer_replay"))
            plain = replay_summary(finding.get("without_sanitizers_replay"))
            lines.append(
                f"| `{input_name}` | `{finding['symptom']}` | {sanitizer} | {plain} "
                f"| `{finding.get('status', 'unknown')}` |"
            )
        lines.append("")
    if final:
        lines.extend(["## Final scope coverage", "", "| Scope | Lines | Branches |", "| --- | ---: | ---: |"])
        for scope in final.get("scopes", []):
            line = scope["lines"]
            branch = scope["branches"]
            line_text = "N/A" if line["percent"] is None else f"{line['covered']}/{line['total']} ({line['percent']}%)"
            branch_text = "N/A" if branch["percent"] is None else f"{branch['covered']}/{branch['total']} ({branch['percent']}%)"
            lines.append(f"| {scope['id']} | {line_text} | {branch_text} |")
        lines.append("")
        lines.append(f"- 90% line threshold met for every frozen scope: `{manifest.get('coverage_threshold_met')}`")
        nginx = final.get("nginx_source", {})
        if nginx:
            metric = nginx["lines"]
            lines.append(f"- Whole nginx source lines: `{metric['covered']}/{metric['total']} ({metric['percent']}%)`")
        lines.append("")
    (run_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
    atomic_json(run_dir / "report.json", manifest)


def count_findings_requiring_analysis(findings):
    return sum(finding.get("status") == "needs_analysis" for finding in findings)


def regression_input_files(directory):
    if not directory.is_dir():
        return []
    hex_sources = sorted(
        path for path in directory.glob("*.hex")
        if not path.name.startswith("._")
    )
    missing_decoded = [path.with_suffix("") for path in hex_sources if not path.with_suffix("").is_file()]
    if missing_decoded:
        missing = ", ".join(path.name for path in missing_decoded)
        raise FileNotFoundError(f"decoded regression input(s) missing in {directory}: {missing}")
    return [
        path for path in sorted(directory.iterdir())
        if path.is_file()
        and not path.name.startswith("._")
        and path.name != ".DS_Store"
        and path.suffix.lower() not in (".hex", ".md", ".json", ".txt")
    ]


def regression_failure_detected(exit_code, output):
    expected_diagnostics = (
        "SUMMARY: UndefinedBehaviorSanitizer:",
        "ERROR: AddressSanitizer:",
    )
    return exit_code is not None and exit_code != 0 and any(
        marker in output for marker in expected_diagnostics
    )


def regression_targets():
    regression_root = ROOT / "regressions"
    if not regression_root.is_dir():
        return []
    return [
        path.name for path in sorted(regression_root.iterdir())
        if path.is_dir() and regression_input_files(path)
    ]


def run_regression_check(target):
    activate_target(target)
    regression_dir = ROOT / "regressions" / target
    inputs = regression_input_files(regression_dir)
    result = {"target": target, "passed": True, "cases": []}
    if not inputs:
        print(f"[{target}] no regression fixtures; check skipped", flush=True)
        return result

    clean_fixture_list = regression_dir / "expected-clean.txt"
    expected_clean = set()
    if clean_fixture_list.is_file():
        expected_clean = {
            line.strip()
            for line in clean_fixture_list.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

    for input_path in inputs:
        started = time.monotonic()
        error = None
        try:
            completed = subprocess.run(
                [str(FUZZ_BIN), "-runs=1", str(input_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                timeout=30,
            )
            exit_code = completed.returncode
            output = completed.stdout or ""
        except subprocess.TimeoutExpired as timeout_error:
            exit_code = None
            output = timeout_error.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            error = "timed out after 30 seconds"
        except OSError as os_error:
            exit_code = None
            output = ""
            error = str(os_error)

        reproduced = regression_failure_detected(exit_code, output)
        expects_clean = input_path.name in expected_clean
        passed = (exit_code == 0 and not reproduced) if expects_clean else reproduced
        case = {
            "input": input_path.name,
            "exit_code": exit_code,
            "expected_sanitizer_diagnostic": reproduced,
            "expected_clean": expects_clean,
            "passed": passed,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        if error:
            case["error"] = error
        result["cases"].append(case)
        if passed:
            if expects_clean:
                print(
                    f"[{target}] PASS {input_path.name}: expected clean replay "
                    f"(exit {exit_code})",
                    flush=True,
                )
            else:
                print(
                    f"[{target}] PASS {input_path.name}: expected sanitizer finding "
                    f"(exit {exit_code})",
                    flush=True,
                )
        else:
            result["passed"] = False
            expectation = "clean replay" if expects_clean else "sanitizer finding"
            print(
                f"[{target}] FAIL {input_path.name}: expected {expectation}; "
                f"exit={exit_code}, error={error or 'diagnostic missing'}",
                flush=True,
            )
            if output:
                print("\n".join(output.splitlines()[-20:]), flush=True)
    return result


def replay_summary(replay):
    if not replay or replay.get("exit_code") is None:
        return "not run"
    if replay["exit_code"] == 0:
        return "not reproduced (exit 0)"
    return f"exit {replay['exit_code']}; inspect log"


def coverage_growth(previous, current):
    previous_lines = set()
    current_lines = set()
    previous_branches = {}
    current_branches = {}
    for summary, line_set, branch_map in (
        (previous, previous_lines, previous_branches),
        (current, current_lines, current_branches),
    ):
        for scope in summary.get("scopes", []):
            scope_id = scope["id"]
            line_set.update((scope_id, line) for line in scope["lines"].get("covered_line_ids", []))
            branch_map[scope_id] = scope["branches"].get("covered", 0)
    return bool(current_lines - previous_lines) or any(
        current_branches.get(scope, 0) > previous_branches.get(scope, 0)
        for scope in current_branches
    )


def execute_fuzz(args, kind):
    global STOP_SIGNAL
    STOP_SIGNAL = None
    activate_target(args.target)
    regression_check = None
    if kind == "campaign":
        regression_check = run_regression_check(args.target)
        if not regression_check["passed"]:
            raise SystemExit("regression preflight failed; campaign was not started")
        activate_target(args.target)
    for corpus in args.reuse_corpus:
        corpus_path = pathlib.Path(corpus)
        if not corpus_path.is_dir() and not (corpus_path.is_file() and tarfile.is_tarfile(corpus_path)):
            raise SystemExit(f"reuse corpus does not exist or is not a directory/archive: {corpus}")
    run_id, run_dir = prepare_run(kind, args.run_id)
    for corpus in args.reuse_corpus:
        copy_reuse_corpus(corpus, run_dir / "corpus_in")
    manifest = base_manifest(kind, run_id, run_dir, args)
    if regression_check is not None:
        manifest["regression_check"] = regression_check
    manifest_path = run_dir / "manifest.json"
    atomic_json(manifest_path, manifest)

    command = [
        FUZZ_BIN,
        f"-dict={run_dir / 'dictionary.dict'}",
        f"-artifact_prefix={run_dir / 'artifacts'}/",
        f"-max_len={args.max_len}",
        f"-timeout={args.timeout}",
        f"-rss_limit_mb={args.rss_limit_mb}",
        "-print_final_stats=1",
        f"-seed={args.seed}",
        run_dir / "corpus_out",
        run_dir / "corpus_in",
    ]
    if kind == "smoke":
        command.insert(3, f"-max_total_time={args.seconds}")
    elif kind == "campaign":
        command[1:1] = campaign_resilience_flags()
    manifest_command = command
    if kind == "campaign":
        manifest_command = command[:-2] + [
            f"-max_total_time={args.coverage_check_interval_seconds}",
            *command[-2:],
        ]
    manifest["command"] = [str(item) for item in manifest_command]
    atomic_json(manifest_path, manifest)
    started = time.monotonic()
    campaign_log_path = run_dir / "logs" / "campaign.log" if kind == "campaign" else None
    campaign_context = None
    code = 1
    campaign_stop_reason = None
    try:
        if kind == "campaign":
            baseline_dir = run_dir / "coverage" / "baseline"
            latest_summary = run_coverage(
                [run_dir / "corpus_in", run_dir / "corpus_out"],
                baseline_dir, "baseline", generate_html=False, retain_exports=False,
            )
            manifest["coverage"]["baseline"] = compact_coverage_summary(latest_summary)
            latest_profile = run_dir / "coverage" / "incremental.profdata"
            os.replace(baseline_dir / "merged.profdata", latest_profile)
            shutil.rmtree(baseline_dir, ignore_errors=True)
            known_hashes = {item["sha256"] for item in file_inventory(run_dir / "corpus_in")}
            known_hashes.update(item["sha256"] for item in file_inventory(run_dir / "corpus_out"))
            next_checkpoint = 1
            campaign_round = 0
            campaign_started = time.monotonic()
            last_growth = campaign_started
            classified_names = set()
            campaign_context = {
                "started": started,
                "last_growth": last_growth,
                "plateau_seconds": args.plateau_seconds,
                "scope_lines": sum(
                    scope["lines"]["covered"]
                    for scope in latest_summary.get("scopes", [])
                ),
                "round": 0,
                "round_started": campaign_started,
            }
            campaign_log_event(
                campaign_log_path,
                campaign_context,
                f"watchdog event=started target={args.target} policy=coverage_stagnation "
                f"required_seconds={args.plateau_seconds} clock=monotonic",
            )
            campaign_log_event(
                campaign_log_path,
                campaign_context,
                f"watchdog event=coverage_baseline scope_lines={campaign_context['scope_lines']} "
                f"last_coverage_change_elapsed={elapsed_hms(time.monotonic() - last_growth)}",
            )

            while True:
                total_elapsed = time.monotonic() - campaign_started
                if args.max_seconds and total_elapsed >= args.max_seconds:
                    campaign_stop_reason = "max_time_budget"
                    print(f"Stopping campaign: maximum runtime of {args.max_seconds} seconds reached")
                    break

                round_name = f"round-{campaign_round + 1:04d}"
                round_limit = args.coverage_check_interval_seconds
                if args.max_seconds:
                    remaining = max(1, int(args.max_seconds - total_elapsed))
                    round_limit = min(round_limit, remaining)
                campaign_context.update({
                    "round": campaign_round + 1,
                    "round_started": time.monotonic(),
                    "last_growth": last_growth,
                    "scope_lines": sum(
                        scope["lines"]["covered"]
                        for scope in latest_summary.get("scopes", [])
                    ),
                })
                campaign_log_event(
                    campaign_log_path,
                    campaign_context,
                    f"watchdog event=round_started round={campaign_round + 1} "
                    f"round_limit_seconds={round_limit} scope_lines={campaign_context['scope_lines']}",
                )
                round_command = command[:-2] + [
                    f"-max_total_time={round_limit}",
                    *command[-2:],
                ]
                print(f"Starting campaign batch {campaign_round + 1} for up to {round_limit} seconds")
                round_log = run_dir / f"logs/fuzzer-{round_name}.log"
                code, batch_elapsed = run_logged(
                    round_command,
                    round_log,
                    campaign_log_path=campaign_log_path,
                    campaign_context=campaign_context,
                )
                compact_run_log(round_log)
                round_log_text = read_run_log(round_log)
                campaign_round += 1

                new_findings = classify_artifacts(run_dir, classified_names)
                manifest["findings"].extend(new_findings)
                classified_names.update(path.name for path in (run_dir / "artifacts").iterdir() if path.is_file())
                if not expected_fork_exit(code, manifest["findings"], round_log_text):
                    manifest["fuzzer_exit_code"] = code
                    manifest["error"] = f"fork-mode fuzzer batch exited with {code} without a classified finding"
                    break
                worker_counters = fork_worker_counters(round_log_text)
                if worker_counters is not None:
                    manifest.setdefault("fork_worker_counters", []).append({
                        "round": campaign_round,
                        **worker_counters,
                    })
                if code != 0:
                    manifest.setdefault("ignored_fuzzer_exit_codes", []).append({
                        "round": campaign_round,
                        "exit_code": code,
                        "reason": (
                            "fork supervisor reached its time limit and propagated the last worker exit code"
                            if not new_findings
                            else "fork-mode worker finding was recorded; supervisor continued"
                        ),
                    })
                    code = 0

                new_inputs = []
                for path in sorted((run_dir / "corpus_out").iterdir()):
                    if not path.is_file():
                        continue
                    try:
                        digest = sha256(path)
                        if digest in known_hashes:
                            continue
                        known_hashes.add(digest)
                        new_inputs.append(path)
                    except FileNotFoundError:
                        continue

                grew = False
                if new_inputs:
                    checkpoint_dir = run_dir / "coverage" / "checkpoint-current"
                    shutil.rmtree(checkpoint_dir, ignore_errors=True)
                    current = run_coverage(
                        [], checkpoint_dir, f"checkpoint-{next_checkpoint:04d}",
                        input_paths=new_inputs, base_profile=latest_profile,
                        generate_html=False, retain_exports=False,
                    )
                    os.replace(checkpoint_dir / "merged.profdata", latest_profile)
                    shutil.rmtree(checkpoint_dir, ignore_errors=True)
                    grew = coverage_growth(latest_summary, current)
                    latest_summary = current
                    next_checkpoint += 1
                    if grew:
                        last_growth = time.monotonic()
                        campaign_context["last_growth"] = last_growth
                        campaign_context["scope_lines"] = sum(
                            scope["lines"]["covered"]
                            for scope in latest_summary.get("scopes", [])
                        )

                elapsed_since_growth = time.monotonic() - last_growth
                checkpoint = {
                    "round": campaign_round,
                    "batch_seconds": round(batch_elapsed, 3),
                    "elapsed_seconds": round(time.monotonic() - campaign_started, 3),
                    "seconds_since_growth": round(elapsed_since_growth, 3),
                    "new_corpus_inputs": len(new_inputs),
                    "coverage_increased": grew,
                    "new_findings": len(new_findings),
                    "scopes": [{
                        "id": scope["id"],
                        "covered_lines": scope["lines"]["covered"],
                        "covered_branches": scope["branches"]["covered"],
                    } for scope in latest_summary.get("scopes", [])],
                }
                manifest.setdefault("coverage_checkpoints", []).append(checkpoint)
                atomic_json(manifest_path, manifest)
                campaign_log_event(
                    campaign_log_path,
                    campaign_context,
                    f"watchdog event=coverage_checkpoint round={campaign_round} "
                    f"scope_lines={campaign_context['scope_lines']} "
                    f"coverage_increased={str(grew).lower()} "
                    f"new_inputs={len(new_inputs)} findings={len(new_findings)} "
                    f"idle_seconds={elapsed_since_growth:.1f} required_seconds={args.plateau_seconds}",
                )
                print(
                    f"Campaign batch {campaign_round}: {len(new_findings)} new findings, "
                    f"{len(new_inputs)} new corpus inputs, "
                    f"{elapsed_since_growth:.0f}s without coverage growth"
                )

                if elapsed_since_growth >= args.plateau_seconds:
                    validation_dir = run_dir / "coverage" / "plateau-validation-current"
                    shutil.rmtree(validation_dir, ignore_errors=True)
                    validated_summary = run_coverage(
                        [run_dir / "corpus_in", run_dir / "corpus_out"],
                        validation_dir, f"plateau-validation-{campaign_round:04d}",
                        generate_html=False, retain_exports=False,
                    )
                    if not coverage_growth(latest_summary, validated_summary):
                        manifest["coverage"]["plateau_validation"] = compact_coverage_summary(validated_summary)
                        shutil.rmtree(validation_dir, ignore_errors=True)
                        campaign_stop_reason = "coverage_plateau"
                        code = 0
                        campaign_log_event(
                            campaign_log_path,
                            campaign_context,
                            f"watchdog event=stop_requested reason=coverage_stagnation "
                            f"idle_seconds={elapsed_since_growth:.1f} required_seconds={args.plateau_seconds}",
                        )
                        print(f"Stopping campaign: no LLVM scope coverage growth for {args.plateau_seconds} seconds")
                        break

                    manifest.setdefault("coverage_plateau_restarts", []).append({
                        "round": campaign_round,
                        "reason": "final replay found coverage not seen by the periodic observer",
                        "coverage": [{
                            "id": scope["id"],
                            "covered_lines": scope["lines"]["covered"],
                            "covered_branches": scope["branches"]["covered"],
                        } for scope in validated_summary.get("scopes", [])],
                    })
                    latest_summary = validated_summary
                    os.replace(validation_dir / "merged.profdata", latest_profile)
                    shutil.rmtree(validation_dir, ignore_errors=True)
                    last_growth = time.monotonic()
                    campaign_context["last_growth"] = last_growth
                    print("Final corpus replay found new coverage; resuming campaign with the accumulated corpus")
                    atomic_json(manifest_path, manifest)
                    continue

                if args.max_seconds and time.monotonic() - campaign_started >= args.max_seconds:
                    campaign_stop_reason = "max_time_budget"
                    campaign_log_event(
                        campaign_log_path,
                        campaign_context,
                        f"watchdog event=stop_requested reason=max_time_budget "
                        f"max_seconds={args.max_seconds}",
                    )
                    print(f"Stopping campaign: maximum runtime of {args.max_seconds} seconds reached")
                    code = 0
                    break
        else:
            code, _ = run_logged(command, run_dir / "logs/fuzzer.log")
            manifest["findings"] = classify_artifacts(run_dir)
        if kind == "smoke":
            manifest["coverage"]["baseline"] = run_coverage([run_dir / "corpus_in"], run_dir / "coverage/baseline", "baseline")
        final_coverage = run_coverage(
            [run_dir / "corpus_in", run_dir / "corpus_out"],
            run_dir / "coverage/final", "final", generate_html=False,
            retain_exports=False,
        )
        manifest["coverage"]["final"] = compact_coverage_summary(final_coverage)
        manifest["coverage_threshold_met"] = all(
            scope["lines"]["percent"] is not None and scope["lines"]["percent"] >= 90.0
            for scope in manifest["coverage"]["final"]["scopes"]
        )
        if STOP_SIGNAL is not None:
            manifest["status"] = "interrupted"
            manifest["stop_reason"] = "interrupted"
            manifest["signal"] = signal.Signals(STOP_SIGNAL).name
        elif manifest["findings"]:
            manifest["status"] = "finding"
            manifest["finding_stop_reason"] = finding_stop_reason(manifest["findings"])
            manifest["stop_reason"] = (
                campaign_stop_reason
                if kind == "campaign" and campaign_stop_reason is not None
                else manifest["finding_stop_reason"]
            )
        elif campaign_stop_reason is not None:
            manifest["status"] = "passed"
            manifest["stop_reason"] = campaign_stop_reason
        elif code == 0:
            manifest["status"] = "passed"
            manifest["stop_reason"] = "time_budget" if kind == "smoke" else "fuzzer_exit"
        else:
            manifest["status"] = "failed"
            manifest["stop_reason"] = "infrastructure_error"
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
        manifest["stop_reason"] = "interrupted"
        code = 130
    except Exception as error:
        manifest["status"] = "failed"
        manifest["stop_reason"] = "infrastructure_error"
        manifest["error"] = str(error)
        print(f"error: {error}", file=sys.stderr)
        code = code or 1
    finally:
        manifest["exit_code"] = code
        manifest["duration_seconds"] = round(time.monotonic() - started, 3)
        manifest["finished_at_utc"] = utc_now()
        manifest["corpus"] = summarize_run_corpora(run_dir)
        (run_dir / "coverage" / "incremental.profdata").unlink(missing_ok=True)
        for temporary_coverage in (
            run_dir / "coverage" / "checkpoint-current",
            run_dir / "coverage" / "plateau-validation-current",
        ):
            shutil.rmtree(temporary_coverage, ignore_errors=True)
        for raw_profile in (run_dir / "coverage").rglob("*.profraw"):
            raw_profile.unlink(missing_ok=True)
        atomic_json(manifest_path, manifest)
        write_report(run_dir, manifest)
        if campaign_context is not None:
            campaign_log_event(
                campaign_log_path,
                campaign_context,
                f"watchdog event=finished status={manifest['status']} "
                f"termination={manifest['stop_reason']} exit={code} "
                f"duration={elapsed_hms(time.monotonic() - started)} "
                f"required_seconds={args.plateau_seconds}",
            )
        compact_campaign_round_logs(run_dir / "logs")
        print(f"run directory: {run_dir}")
    return code


def reproduce(args):
    activate_target(args.target)
    input_path = pathlib.Path(args.input)
    if not input_path.is_file():
        raise SystemExit(f"input does not exist: {input_path}")
    binary = COVERAGE_BIN if args.without_sanitizers else FUZZ_BIN
    return subprocess.call([str(binary), "-runs=1", str(input_path)])


def inspect_seed(args):
    activate_target(DEFAULT_TARGET)
    input_path = pathlib.Path(args.input)
    source = input_path.read_bytes()
    encoded = subprocess.run([
        str(PROTOC), f"--proto_path={PROTO.parent}", "--encode=HttpProto", str(PROTO)
    ], input=source, stdout=subprocess.PIPE)
    if encoded.returncode != 0:
        return encoded.returncode
    return subprocess.run([
        str(PROTOC), f"--proto_path={PROTO.parent}", "--decode=HttpProto", str(PROTO)
    ], input=encoded.stdout).returncode


def coverage_existing(args):
    activate_target(args.target)
    run_dir = RUNS / TARGET / args.run_id
    if not run_dir.is_dir():
        raise SystemExit(f"run does not exist: {run_dir}")
    output = run_dir / "coverage" / f"recheck-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    with tempfile.TemporaryDirectory(prefix="nginx-fuzz-recheck-") as temporary:
        corpus_dirs = materialize_run_corpus(run_dir, pathlib.Path(temporary) / "corpus")
        summary = run_coverage(
            corpus_dirs, output, "recheck", generate_html=False, retain_exports=False
        )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def minimize_corpus(args):
    activate_target(args.target)
    run_dir = RUNS / TARGET / args.run_id
    if not run_dir.is_dir():
        raise SystemExit(f"run does not exist: {run_dir}")
    output = run_dir / "corpus_min"
    output.mkdir(exist_ok=True)
    if any(output.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty minimized corpus: {output}")
    with tempfile.TemporaryDirectory(prefix="nginx-fuzz-minimize-") as temporary:
        corpus_dirs = materialize_run_corpus(run_dir, pathlib.Path(temporary) / "corpus")
        command = [str(FUZZ_BIN), "-merge=1", str(output), *map(str, corpus_dirs)]
        code, _ = run_logged(command, run_dir / "logs/corpus-minimize.log")
        compact_run_log(run_dir / "logs/corpus-minimize.log")
        if code != 0:
            return code
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        before = run_coverage(
            corpus_dirs, run_dir / "coverage" / f"pre-minimize-{stamp}",
            "pre-minimize", generate_html=False, retain_exports=False,
        )
        after = run_coverage(
            [output], run_dir / "coverage" / f"post-minimize-{stamp}",
            "post-minimize", generate_html=False, retain_exports=False,
        )
    before_lines = {scope["id"]: scope["lines"]["covered_line_ids"] for scope in before["scopes"]}
    after_lines = {scope["id"]: scope["lines"]["covered_line_ids"] for scope in after["scopes"]}
    if before_lines != after_lines:
        print("minimized corpus does not preserve exact scoped line coverage", file=sys.stderr)
        return 2
    print(f"minimized corpus: {output}")
    return 0


def minimize_crash(args):
    activate_target(args.target)
    source = pathlib.Path(args.input)
    destination = pathlib.Path(args.output)
    if not source.is_file():
        raise SystemExit(f"input does not exist: {source}")
    if destination.exists():
        raise SystemExit(f"refusing to overwrite: {destination}")
    return subprocess.call([
        str(FUZZ_BIN), "-minimize_crash=1",
        f"-exact_artifact_path={destination}", str(source)
    ])


def add_fuzz_options(parser, include_seconds=False, default_seconds=None):
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET)
    if include_seconds:
        parser.add_argument("--seconds", type=int, default=default_seconds)
    parser.add_argument("--max-len", type=int, default=65536)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--rss-limit-mb", type=int, default=2048)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--run-id")
    parser.add_argument("--reuse-corpus", action="append", default=[])


def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    parser = argparse.ArgumentParser(description="Reproducible nginx fuzzing runner")
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_fuzz_options(subparsers.add_parser("smoke"), include_seconds=True, default_seconds=60)
    campaign_parser = subparsers.add_parser("campaign")
    add_fuzz_options(campaign_parser)
    campaign_parser.add_argument("--plateau-seconds", type=int, default=7200)
    campaign_parser.add_argument("--coverage-check-interval-seconds", type=int, default=300)
    campaign_parser.add_argument("--max-seconds", type=int, default=0)
    replay = subparsers.add_parser("reproduce")
    replay.add_argument("target")
    replay.add_argument("input")
    replay.add_argument("--without-sanitizers", action="store_true")
    inspect_parser = subparsers.add_parser("inspect-seed")
    inspect_parser.add_argument("input")
    coverage_parser = subparsers.add_parser("coverage")
    coverage_parser.add_argument("target")
    coverage_parser.add_argument("run_id")
    minimize_parser = subparsers.add_parser("minimize-corpus")
    minimize_parser.add_argument("target")
    minimize_parser.add_argument("run_id")
    crash_parser = subparsers.add_parser("minimize-crash")
    crash_parser.add_argument("target")
    crash_parser.add_argument("input")
    crash_parser.add_argument("output")
    regression_parser = subparsers.add_parser("regression-check")
    regression_parser.add_argument("target", nargs="?", help="target to check (default: all with fixtures)")
    subparsers.add_parser("help")
    args = parser.parse_args()

    if args.command == "smoke" and args.seconds < 1:
        parser.error("--seconds must be positive")
    if args.command == "campaign":
        if args.plateau_seconds < 1 or args.coverage_check_interval_seconds < 1:
            parser.error("plateau and coverage-check intervals must be positive")
        if args.max_seconds < 0:
            parser.error("--max-seconds cannot be negative")

    if args.command == "help":
        parser.print_help()
        return 0
    if args.command in ("smoke", "campaign"):
        return execute_fuzz(args, args.command)
    if args.command == "reproduce":
        return reproduce(args)
    if args.command == "inspect-seed":
        return inspect_seed(args)
    if args.command == "coverage":
        return coverage_existing(args)
    if args.command == "minimize-corpus":
        return minimize_corpus(args)
    if args.command == "minimize-crash":
        return minimize_crash(args)
    if args.command == "regression-check":
        targets = [args.target] if args.target else regression_targets()
        if not targets:
            print("no regression fixtures found", flush=True)
            return 0
        checks = [run_regression_check(target) for target in targets]
        return 0 if all(check["passed"] for check in checks) else 1
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
