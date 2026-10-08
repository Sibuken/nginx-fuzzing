// Direct target for nginx's HTTP/2 frame-header state machine.  The
// build-only hook temporarily substitutes side-effect-free body handlers;
// ngx_http_v2_state_head itself and its real type dispatch remain unchanged.
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_v2_fuzz_frame_header(u_char *data, size_t len);
}

#include <cstddef>
#include <cstdint>

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    u_char *input = const_cast<u_char *>(data);
    size_t limit = size < 9 ? size : 9;

    // Exercise every incremental prefix as received by the state machine,
    // then the complete header.  The hook itself caps input at nine bytes.
    for (size_t visible = 0; visible <= limit; visible++) {
        if (ngx_http_v2_fuzz_frame_header(input, visible) != NGX_OK) {
            __builtin_trap();
        }
    }

    return 0;
}
