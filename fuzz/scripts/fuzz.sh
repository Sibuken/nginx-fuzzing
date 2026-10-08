#!/bin/sh

set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
image=${FUZZ_IMAGE:-nginx-fuzz:1.30.5}
runs_dir=${FUZZ_RUNS_DIR:-"${project_root}/fuzz/runs"}

usage() {
    echo "usage: $0 build | smoke [target] [options] | smoke-all [options] | campaign [target] [options] | campaign-parallel [targets...] [options] | regression-check [target] | coverage target run-id | minimize-corpus target run-id | minimize-crash target input output | inspect-seed path | reproduce target path [--without-sanitizers]" >&2
    exit 64
}

command=${1:-}
[ -n "${command}" ] || usage
shift

case "${command}" in
    build)
        revision=$(git -C "${project_root}" rev-parse HEAD 2>/dev/null || printf unknown)
        host_arch=$(uname -m)
        tar -C "${project_root}" \
            --exclude='./.dockerignore' \
            --exclude='./.git' \
            --exclude='./tests' \
            --exclude='./fuzz/runs' \
            -cf - . \
        | docker build \
            --platform linux/amd64 \
            --build-arg "NGINX_REVISION=${revision}" \
            --build-arg "HOST_ARCHITECTURE=${host_arch}" \
            --tag "${image}" \
            --file "fuzz/docker/Dockerfile" \
            -
        ;;
    smoke|campaign)
        target=${1:-NGX-OSS-HTTP}
        if [ "$#" -gt 0 ]; then shift; fi
        mkdir -p "${runs_dir}"
        image_id=$(docker image inspect --format '{{.Id}}' "${image}" 2>/dev/null || printf unknown)
        exec docker run --rm --init --platform linux/amd64 --ulimit nofile=65536:65536 \
            --env "FUZZ_IMAGE_REFERENCE=${image}" \
            --env "FUZZ_IMAGE_ID=${image_id}" \
            --volume "${runs_dir}:/runs" \
            "${image}" "${command}" "${target}" "$@"
        ;;
    regression-check)
        mkdir -p "${runs_dir}"
        exec docker run --rm --init --platform linux/amd64 \
            --volume "${runs_dir}:/runs" \
            "${image}" regression-check "$@"
        ;;
    smoke-all)
        status=0
        for target in NGX-OSS-HTTP NGX-IF06 NGX-IF07 NGX-IF08 NGX-IF09 NGX-IF10 NGX-IF11 NGX-IF12 NGX-IF13 NGX-IF14 NGX-IF15 NGX-IF16 NGX-IF17 NGX-IF18 NGX-IF19 NGX-IF20 NGX-IF21; do
            if ! "${project_root}/fuzz/scripts/fuzz.sh" smoke "${target}" "$@"; then
                status=1
            fi
        done
        exit "${status}"
        ;;
    campaign-parallel)
        mkdir -p "${runs_dir}"
        "${project_root}/fuzz/scripts/fuzz.sh" build
        exec env FUZZ_IMAGE="${image}" FUZZ_RUNS_DIR="${runs_dir}" \
            python3 "${project_root}/fuzz/scripts/campaign-parallel.py" "$@"
        ;;
    inspect-seed)
        [ "$#" -eq 1 ] || usage
        exec docker run --rm --init --platform linux/amd64 \
            --volume "${project_root}:${project_root}:ro" \
            "${image}" inspect-seed "$1"
        ;;
    reproduce|coverage|minimize-corpus|minimize-crash)
        [ "$#" -ge 2 ] || usage
        mkdir -p "${runs_dir}"
        exec docker run --rm --init --platform linux/amd64 \
            --volume "${runs_dir}:/runs" \
            "${image}" "${command}" "$@"
        ;;
    *)
        usage
        ;;
esac
