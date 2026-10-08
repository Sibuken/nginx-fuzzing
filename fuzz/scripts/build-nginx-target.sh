#!/bin/bash

set -euo pipefail

if [[ $# -ne 6 ]]; then
    echo "usage: $0 MODE SOURCE_DIR PROJECT_DIR LPM_SOURCE LPM_BUILD OUT_DIR" >&2
    exit 64
fi

mode=$1
source_dir=$2
project_dir=$3
lpm_source=$4
lpm_build=$5
out_dir=$6
build_dir="/work/nginx-${mode}"

case "${mode}" in
    fuzz)
        # nginx deliberately uses unaligned integer loads in the HTTP parser on
        # architectures where NGX_HAVE_NONALIGNED is enabled.  They are valid on
        # the pinned linux/amd64 platform, but UBSan's alignment check diagnoses
        # them before the remaining sanitizers can exercise the parser.
        common_flags="-O1 -gline-tables-only -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize=alignment -fno-sanitize-recover=undefined"
        fuzzing_engine="-fsanitize=fuzzer,address,undefined -fno-sanitize=alignment -fno-sanitize-recover=undefined"
        ;;
    coverage)
        common_flags="-O1 -g -fprofile-instr-generate -fcoverage-mapping"
        fuzzing_engine="-fsanitize=fuzzer -fprofile-instr-generate"
        ;;
    *)
        echo "unsupported mode: ${mode}" >&2
        exit 64
        ;;
esac

mkdir -p "${build_dir}" "${out_dir}"
cp -a "${source_dir}/." "${build_dir}/"

cd "${build_dir}"
patch --batch --forward --fuzz=0 -p1 < "${project_dir}/add_fuzzers.diff"
cp -a "${project_dir}/fuzz" src/fuzz
cp "${project_dir}/make_fuzzers" auto/make_fuzzers
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0001-nginx-1.30-setup-checks.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0003-nginx-per-input-cleanup.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0002-add-proxy-protocol-target.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0004-add-dns-response-hook.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0005-expose-config-tokenizer.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0006-expose-http2-parser-hooks.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0007-add-http2-control-frame-hook.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0008-add-http2-header-block-hook.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0009-add-http2-pseudo-header-hook.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0010-add-http2-live-header-block-hook.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0011-add-http2-live-headers-frame-hook.patch
git apply --whitespace=nowarn /repo/fuzz/patches/0012-add-http2-response-trailers-hook.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0013-add-http2-response-trailers-target.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0014-add-http2-upstream-trailers-hook.patch
patch --batch --forward --fuzz=0 -p1 < /repo/fuzz/patches/0015-add-http2-upstream-trailers-target.patch
cp /repo/fuzz/targets/NGX-IF06/proxy_protocol_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF07/dns_response_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF08/proxy_protocol_tlv_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF09/config_parser_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF10/hpack_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF11/http2_frame_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF12/http2_control_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF13/http2_rst_stream_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF14/http2_data_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF15/http2_headers_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF16/http2_pseudo_headers_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF17/http2_request_headers_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF18/http2_headers_state_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF20/http2_response_trailers_fuzzer.cc src/fuzz/
cp /repo/fuzz/targets/NGX-IF21/http2_upstream_trailers_fuzzer.cc src/fuzz/

mkdir -p src/fuzz/genfiles
(
    cd src/fuzz
    "${lpm_build}/external.protobuf/bin/protoc" \
        http_request_proto.proto \
        --cpp_out=genfiles
)

export CC=clang-14
export CXX=clang++-14
export CFLAGS="${common_flags}"
export CXXFLAGS="${common_flags}"
export LIB_FUZZING_ENGINE="${fuzzing_engine}"
export SRC=/opt/upstream-project

./auto/configure \
    --with-ld-opt="-Wl,--wrap=listen -Wl,--wrap=setsockopt -Wl,--wrap=bind -Wl,--wrap=shutdown -Wl,--wrap=connect -Wl,--wrap=getpwnam -Wl,--wrap=getgrnam -Wl,--wrap=chmod -Wl,--wrap=chown -Wl,--wrap=ngx_destroy_pool -Wl,--wrap=ngx_handle_write_event -Wl,--wrap=ngx_tcp_push -Wl,--wrap=ngx_tcp_nodelay" \
    --with-cc-opt="-DNGX_DEBUG_PALLOC=1 ${common_flags}" \
    --with-http_v2_module

make -f objs/Makefile -j"$(nproc)" fuzzers
cp objs/http_request_fuzzer "${out_dir}/"
cp objs/proxy_protocol_fuzzer "${out_dir}/"
cp objs/dns_response_fuzzer "${out_dir}/"
cp objs/proxy_protocol_tlv_fuzzer "${out_dir}/"
cp objs/config_parser_fuzzer "${out_dir}/"
cp objs/hpack_fuzzer "${out_dir}/"
cp objs/http2_frame_fuzzer "${out_dir}/"
cp objs/http2_control_fuzzer "${out_dir}/"
cp objs/http2_rst_stream_fuzzer "${out_dir}/"
cp objs/http2_data_fuzzer "${out_dir}/"
cp objs/http2_headers_fuzzer "${out_dir}/"
cp objs/http2_pseudo_headers_fuzzer "${out_dir}/"
cp objs/http2_request_headers_fuzzer "${out_dir}/"
cp objs/http2_headers_state_fuzzer "${out_dir}/"
cp objs/http2_response_trailers_fuzzer "${out_dir}/"
cp objs/http2_upstream_trailers_fuzzer "${out_dir}/"
cp src/fuzz/http_request_proto.proto "${out_dir}/"
cp src/fuzz/http_request_fuzzer.dict "${out_dir}/upstream.dict"
cp objs/ngx_auto_config.h "${out_dir}/"
printf '%s\n' "${common_flags}" > "${out_dir}/compile-flags.txt"
printf '%s\n' "${fuzzing_engine}" > "${out_dir}/link-flags.txt"
