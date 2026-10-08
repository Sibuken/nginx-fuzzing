// Stateful target for HTTP/2 RST_STREAM frames. The isolated build-only
// driver creates a minimal live stream and invokes nginx's real handler.
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_v2_fuzz_control_frames(ngx_pool_t *pool, ngx_log_t *log,
    u_char *data, size_t len, size_t chunk, ngx_uint_t allow_control_frames,
    ngx_uint_t allow_rst_stream, ngx_uint_t allow_data_frame,
    ngx_uint_t data_mode);
}

#include <cstddef>
#include <cstdint>
#include <cstdlib>

static ngx_log_t fuzz_log;
static ngx_open_file_t fuzz_log_file;
static ngx_cycle_t fuzz_cycle;

static int
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
    return 0;
}

static void
run_fragmentation(const uint8_t *data, size_t size, size_t chunk)
{
    ngx_pool_t *pool = ngx_create_pool(4096, &fuzz_log);
    if (pool == nullptr) {
        std::abort();
    }

    ngx_int_t rc = ngx_http_v2_fuzz_control_frames(
        pool, &fuzz_log, const_cast<u_char *>(data), size, chunk, 1, 1, 0, 0);

    ngx_destroy_pool(pool);

    if (rc != NGX_OK) {
        __builtin_trap();
    }
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int initialized = initialize_runtime();
    (void) initialized;

    if (size > 4096) {
        return 0;
    }

    size_t selected = size == 0 ? 1 : 1 + (data[0] & 15);

    run_fragmentation(data, size, size == 0 ? 1 : size);
    run_fragmentation(data, size, 1);
    run_fragmentation(data, size, 3);
    run_fragmentation(data, size, selected);
    return 0;
}
