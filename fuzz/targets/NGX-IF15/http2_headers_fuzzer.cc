// Direct target for nginx's HPACK header-block state machine.  The target
// supplies valid HEADERS/CONTINUATION framing and lets nginx decode the block
// and maintain its real per-connection dynamic table.
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_v2_fuzz_header_block(u_char *data, size_t len,
    size_t *consumed);
}

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

static void
append_frame(std::vector<u_char> &wire, u_char type, u_char flags,
    const u_char *payload, size_t len)
{
    wire.push_back(static_cast<u_char>((len >> 16) & 0xff));
    wire.push_back(static_cast<u_char>((len >> 8) & 0xff));
    wire.push_back(static_cast<u_char>(len & 0xff));
    wire.push_back(type);
    wire.push_back(flags);
    wire.push_back(0);
    wire.push_back(0);
    wire.push_back(0);
    wire.push_back(1);
    if (len != 0) {
        wire.insert(wire.end(), payload, payload + len);
    }
}

static void
run_block(const uint8_t *data, size_t size, size_t chunk)
{
    std::vector<u_char> wire;
    size_t offset = 0;
    size_t first = std::min(size, chunk);

    append_frame(wire, 1, first == size ? 4 : 0, data, first);
    offset += first;

    while (offset < size) {
        size_t count = std::min(chunk, size - offset);
        u_char flags = offset + count == size ? 4 : 0;

        append_frame(wire, 9, flags, data + offset, count);
        offset += count;
    }

    size_t consumed = 0;
    if (ngx_http_v2_fuzz_header_block(wire.data(), wire.size(), &consumed)
        != NGX_OK
        || consumed > wire.size())
    {
        __builtin_trap();
    }
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 4096) {
        return 0;
    }

    size_t selected = size == 0 ? 1 : 1 + (data[0] & 63);
    run_block(data, size, size == 0 ? 1 : size);
    run_block(data, size, 1);
    run_block(data, size, 3);
    run_block(data, size, selected);

    return 0;
}
