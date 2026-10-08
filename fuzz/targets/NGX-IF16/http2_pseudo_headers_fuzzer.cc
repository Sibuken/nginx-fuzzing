// Exercises nginx's real HTTP/2 pseudo-header validation/parsers against a
// minimal synthetic request and stream. Input is a sequence of byte-sized
// name/value lengths followed by the corresponding bytes.
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_v2_fuzz_pseudo_headers(u_char *data, size_t len);
}

#include <cstddef>
#include <cstdint>
#include <cstdlib>

static ngx_log_t fuzz_log;
static ngx_open_file_t fuzz_log_file;
static ngx_cycle_t fuzz_cycle;

static void
initialize_runtime()
{
    ngx_time_init();
    ngx_strerror_init();
    fuzz_log_file.fd = ngx_stderr;
    fuzz_log.file = &fuzz_log_file;
    fuzz_log.log_level = 0;
    fuzz_cycle.log = &fuzz_log;
    fuzz_cycle.new_log = fuzz_log;
    ngx_cycle = &fuzz_cycle;
    if (ngx_preinit_modules() != NGX_OK) {
        std::abort();
    }
    fuzz_cycle.modules = ngx_modules;
    (void) ngx_count_modules(&fuzz_cycle, NGX_HTTP_MODULE);
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const bool initialized = (initialize_runtime(), true);
    (void) initialized;
    if (size <= 4096) {
        (void) ngx_http_v2_fuzz_pseudo_headers(
            const_cast<u_char *>(data), size);
    }
    return 0;
}
