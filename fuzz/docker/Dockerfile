# syntax=docker/dockerfile:1

FROM --platform=linux/amd64 debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS build

ARG OSS_FUZZ_REVISION=2cc3fa481cbf724c0091fd3c75fdd4142e698409
ARG OSS_FUZZ_ARCHIVE_URL=https://github.com/google/oss-fuzz/archive/2cc3fa481cbf724c0091fd3c75fdd4142e698409.tar.gz
ARG OSS_FUZZ_ARCHIVE_SHA256=07dc5e75c112d4a0855122f1fee3bd15f15a97c8220f39857f328640940c15db
ARG LPM_REVISION=c1c950eae0440c3808f2b8bd7c57d0c6a42c1a90
ARG LPM_ARCHIVE_URL=https://github.com/google/libprotobuf-mutator/archive/c1c950eae0440c3808f2b8bd7c57d0c6a42c1a90.tar.gz
ARG LPM_ARCHIVE_SHA256=260408230cbb08009da01fb2445ac75e08576d85b57da47ad0a794b91429803f
ARG NGINX_REVISION=4556c714d1cfa587f92c7c0365c09209d42d148b
ARG HOST_ARCHITECTURE=arm64

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang-14 \
        cmake \
        curl \
        file \
        git \
        libclang-rt-14-dev \
        libcrypt-dev \
        libfuzzer-14-dev \
        libpcre2-dev \
        llvm-14 \
        make \
        ninja-build \
        patch \
        python3 \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY fuzz/scripts/fetch-upstream.sh /usr/local/bin/fetch-upstream
COPY fuzz/vendor-cache/ /tmp/vendor-cache/

RUN chmod +x /usr/local/bin/fetch-upstream \
    && fetch-upstream \
        "${OSS_FUZZ_ARCHIVE_URL}" \
        "${OSS_FUZZ_ARCHIVE_SHA256}" \
        /tmp/vendor-cache/oss-fuzz.tar.gz \
        "${LPM_ARCHIVE_URL}" \
        "${LPM_ARCHIVE_SHA256}" \
        /tmp/vendor-cache/libprotobuf-mutator.tar.gz \
        /opt/pinned \
    && mkdir -p /opt/upstream-project \
    && cp -a /opt/pinned/oss-fuzz/projects/nginx/. /opt/upstream-project/ \
    && ln -s /opt/pinned/libprotobuf-mutator /opt/upstream-project/libprotobuf-mutator

RUN cmake \
        -S /opt/pinned/libprotobuf-mutator \
        -B /opt/lpm-build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang-14 \
        -DCMAKE_CXX_COMPILER=clang++-14 \
        -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON \
        -DLIB_PROTO_MUTATOR_EXAMPLES=OFF \
        -DLIB_PROTO_MUTATOR_TESTING=OFF \
    && cmake --build /opt/lpm-build --parallel \
    && ln -s /opt/lpm-build /opt/upstream-project/LPM

WORKDIR /repo
COPY auto /repo/auto
COPY conf /repo/conf
COPY src /repo/src
COPY LICENSE /repo/LICENSE
COPY fuzz/scripts/build-nginx-target.sh /repo/fuzz/scripts/build-nginx-target.sh
COPY fuzz/scripts/fetch-upstream.sh /repo/fuzz/scripts/fetch-upstream.sh
COPY fuzz/patches /repo/fuzz/patches
COPY fuzz/targets /repo/fuzz/targets

RUN chmod +x \
        /repo/fuzz/scripts/build-nginx-target.sh \
        /repo/fuzz/scripts/fetch-upstream.sh \
    && mkdir -p /opt/nginx-source \
    && cp -a /repo/auto /repo/conf /repo/src /repo/LICENSE /opt/nginx-source/ \
    && /repo/fuzz/scripts/build-nginx-target.sh \
        fuzz /opt/nginx-source /opt/upstream-project \
        /opt/pinned/libprotobuf-mutator /opt/lpm-build /opt/fuzz/bin/fuzz \
    && /repo/fuzz/scripts/build-nginx-target.sh \
        coverage /opt/nginx-source /opt/upstream-project \
        /opt/pinned/libprotobuf-mutator /opt/lpm-build /opt/fuzz/bin/coverage

COPY fuzz/seeds /repo/fuzz/seeds
COPY fuzz/dict /repo/fuzz/dict

RUN mkdir -p /opt/fuzz/seeds/NGX-OSS-HTTP /opt/fuzz/seeds/NGX-IF06 \
        /opt/fuzz/seeds/NGX-IF07 /opt/fuzz/seeds/NGX-IF08 \
        /opt/fuzz/seeds/NGX-IF09 /opt/fuzz/seeds/NGX-IF10 \
        /opt/fuzz/seeds/NGX-IF11 /opt/fuzz/seeds/NGX-IF12 \
        /opt/fuzz/seeds/NGX-IF13 /opt/fuzz/seeds/NGX-IF14 \
        /opt/fuzz/seeds/NGX-IF15 /opt/fuzz/seeds/NGX-IF16 /opt/fuzz/seeds/NGX-IF17 \
        /opt/fuzz/seeds/NGX-IF18 /opt/fuzz/seeds/NGX-IF19 /opt/fuzz/seeds/NGX-IF20 /opt/fuzz/seeds/NGX-IF21 \
        /opt/fuzz/dict \
    && for source in /repo/fuzz/seeds/NGX-OSS-HTTP/textproto/*.textproto; do \
        name="$(basename "${source}")"; \
        (cd /opt/fuzz/bin/fuzz && \
            /opt/lpm-build/external.protobuf/bin/protoc \
                --proto_path=. \
                --encode=HttpProto \
                http_request_proto.proto \
                < "${source}" \
                > /dev/null); \
        cp "${source}" "/opt/fuzz/seeds/NGX-OSS-HTTP/${name}"; \
    done \
    && for target in NGX-IF06 NGX-IF07 NGX-IF08 NGX-IF09 NGX-IF10 NGX-IF11 NGX-IF12 NGX-IF13 NGX-IF14 NGX-IF15 NGX-IF16 NGX-IF17 NGX-IF18 NGX-IF19 NGX-IF20 NGX-IF21; do \
      for source in /repo/fuzz/seeds/${target}/*.hex; do \
        name="$(basename "${source}" .hex)"; \
        python3 -c 'import pathlib,sys; pathlib.Path(sys.argv[2]).write_bytes(bytes.fromhex(pathlib.Path(sys.argv[1]).read_text()))' \
            "${source}" "/opt/fuzz/seeds/${target}/${name}"; \
      done; \
    done \
    && cp /repo/fuzz/dict/NGX-OSS-HTTP.dict /opt/fuzz/dict/local.dict \
    && cp /opt/fuzz/bin/fuzz/upstream.dict /opt/fuzz/dict/upstream.dict \
    && sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' /opt/fuzz/dict/upstream.dict > /opt/fuzz/dict/NGX-OSS-HTTP.dict \
    && sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' /opt/fuzz/dict/local.dict >> /opt/fuzz/dict/NGX-OSS-HTTP.dict \
    && cp /repo/fuzz/dict/NGX-IF06.dict /opt/fuzz/dict/NGX-IF06.dict \
    && cp /repo/fuzz/dict/NGX-IF07.dict /opt/fuzz/dict/NGX-IF07.dict \
    && cp /repo/fuzz/dict/NGX-IF08.dict /opt/fuzz/dict/NGX-IF08.dict \
    && cp /repo/fuzz/dict/NGX-IF09.dict /opt/fuzz/dict/NGX-IF09.dict \
    && cp /repo/fuzz/dict/NGX-IF10.dict /opt/fuzz/dict/NGX-IF10.dict \
    && cp /repo/fuzz/dict/NGX-IF11.dict /opt/fuzz/dict/NGX-IF11.dict \
    && cp /repo/fuzz/dict/NGX-IF12.dict /opt/fuzz/dict/NGX-IF12.dict \
    && cp /repo/fuzz/dict/NGX-IF13.dict /opt/fuzz/dict/NGX-IF13.dict \
    && cp /repo/fuzz/dict/NGX-IF14.dict /opt/fuzz/dict/NGX-IF14.dict \
    && cp /repo/fuzz/dict/NGX-IF15.dict /opt/fuzz/dict/NGX-IF15.dict \
    && cp /repo/fuzz/dict/NGX-IF16.dict /opt/fuzz/dict/NGX-IF16.dict \
    && cp /repo/fuzz/dict/NGX-IF17.dict /opt/fuzz/dict/NGX-IF17.dict \
    && cp /repo/fuzz/dict/NGX-IF18.dict /opt/fuzz/dict/NGX-IF18.dict \
    && cp /repo/fuzz/dict/NGX-IF19.dict /opt/fuzz/dict/NGX-IF19.dict \
    && cp /repo/fuzz/dict/NGX-IF20.dict /opt/fuzz/dict/NGX-IF20.dict \
    && cp /repo/fuzz/dict/NGX-IF21.dict /opt/fuzz/dict/NGX-IF21.dict

COPY fuzz/upstream.lock.json /opt/fuzz/upstream.lock.json
COPY fuzz/targets /opt/fuzz/targets
COPY fuzz/patches /opt/fuzz/patches
COPY fuzz/regressions /opt/fuzz/regressions
COPY fuzz/scripts/runner.py /usr/local/bin/nginx-fuzz

RUN chmod +x /usr/local/bin/nginx-fuzz \
    && for target in NGX-IF07 NGX-IF14; do \
      for source in /opt/fuzz/regressions/${target}/*.hex; do \
        output="${source%.hex}"; \
        python3 -c 'import pathlib,sys; pathlib.Path(sys.argv[2]).write_bytes(bytes.fromhex(pathlib.Path(sys.argv[1]).read_text()))' \
            "${source}" "${output}"; \
      done; \
    done \
    && mkdir -p /runs \
    && sed -n 's/^#define NGINX_VERSION[[:space:]]*"\([^"]*\)"/\1/p' /opt/nginx-source/src/core/nginx.h > /opt/fuzz/nginx-version.txt \
    && printf '%s\n' "${NGINX_REVISION}" > /opt/fuzz/nginx-revision.txt \
    && printf '%s\n' "${HOST_ARCHITECTURE}" > /opt/fuzz/host-architecture.txt \
    && find /opt/nginx-source -type f -print0 \
        | sort -z \
        | xargs -0 sha256sum \
        | sha256sum \
        | cut -d' ' -f1 > /opt/fuzz/nginx-source.sha256 \
    && clang-14 --version > /opt/fuzz/toolchain.txt \
    && llvm-cov-14 --version >> /opt/fuzz/toolchain.txt \
    && /opt/lpm-build/external.protobuf/bin/protoc --version >> /opt/fuzz/toolchain.txt

ENV ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:symbolize=1 \
    UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
    PATH=/usr/lib/llvm-14/bin:${PATH}

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/nginx-fuzz"]
CMD ["help"]
