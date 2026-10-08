#!/bin/sh

set -eu

if [ "$#" -ne 7 ]; then
    echo "usage: $0 OSS_URL OSS_SHA OSS_CACHE LPM_URL LPM_SHA LPM_CACHE DEST" >&2
    exit 64
fi

oss_url=$1
oss_sha=$2
oss_cache=$3
lpm_url=$4
lpm_sha=$5
lpm_cache=$6
dest=$7

mkdir -p "${dest}/downloads" "${dest}/oss-fuzz" "${dest}/libprotobuf-mutator"

fetch_and_verify() {
    url=$1
    expected=$2
    cached=$3
    output=$4

    if [ -f "${cached}" ]; then
        cp "${cached}" "${output}"
    else
        curl --fail --location --show-error --silent "${url}" --output "${output}"
    fi

    printf '%s  %s\n' "${expected}" "${output}" | sha256sum --check --status
}

fetch_and_verify "${oss_url}" "${oss_sha}" "${oss_cache}" "${dest}/downloads/oss-fuzz.tar.gz"
fetch_and_verify "${lpm_url}" "${lpm_sha}" "${lpm_cache}" "${dest}/downloads/libprotobuf-mutator.tar.gz"

tar -xzf "${dest}/downloads/oss-fuzz.tar.gz" --strip-components=1 -C "${dest}/oss-fuzz"
tar -xzf "${dest}/downloads/libprotobuf-mutator.tar.gz" --strip-components=1 -C "${dest}/libprotobuf-mutator"

