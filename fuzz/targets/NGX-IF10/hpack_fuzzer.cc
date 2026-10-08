// Direct target for the HPACK Huffman decoder and variable-length integer
// decoder used by nginx's HTTP/2 implementation.
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_v2_fuzz_parse_int(u_char *data, size_t len,
    ngx_uint_t prefix, size_t logical_length, size_t *consumed,
    size_t *remaining);
}

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

static ngx_log_t fuzz_log;
static volatile u_char fuzz_sink;

struct DecodeResult {
    ngx_int_t rc;
    u_char state;
    std::vector<u_char> output;
};

static DecodeResult
decode(const uint8_t *data, size_t size, size_t chunk)
{
    DecodeResult result = { NGX_OK, 0, {} };
    result.output.resize(size * 2 + 1);
    u_char *dst = result.output.data();

    if (size == 0) {
        result.rc = ngx_http_huff_decode(&result.state,
                                        const_cast<u_char *>(data), 0, &dst,
                                        1, &fuzz_log);
    }

    for (size_t offset = 0; offset < size; ) {
        size_t count = chunk;
        if (count > size - offset) {
            count = size - offset;
        }
        ngx_uint_t last = offset + count == size;
        result.rc = ngx_http_huff_decode(&result.state,
                     const_cast<u_char *>(data + offset), count, &dst, last,
                     &fuzz_log);
        if (result.rc != NGX_OK) {
            break;
        }
        offset += count;
    }

    result.output.resize(static_cast<size_t>(dst - result.output.data()));
    return result;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t chunk = size == 0 ? 1 : 1 + (data[0] & 31);
    DecodeResult one_shot = decode(data, size, size == 0 ? 1 : size);
    DecodeResult fragmented = decode(data, size, chunk);

    if (one_shot.rc != fragmented.rc
        || one_shot.state != fragmented.state
        || one_shot.output != fragmented.output)
    {
        __builtin_trap();
    }

    for (ngx_uint_t prefix : { 0x0fu, 0x1fu, 0x3fu, 0x7fu }) {
        size_t consumed = 0;
        size_t remaining = 0;
        size_t logical = size == 0 ? 0 : (data[0] % (size + 1));
        ngx_int_t rc = ngx_http_v2_fuzz_parse_int(
            const_cast<u_char *>(data), size, prefix, logical,
            &consumed, &remaining);

        if (consumed > size || remaining > logical) {
            __builtin_trap();
        }
        fuzz_sink ^= static_cast<u_char>(rc);
        fuzz_sink ^= static_cast<u_char>(consumed);
        fuzz_sink ^= static_cast<u_char>(remaining);
    }

    return 0;
}
