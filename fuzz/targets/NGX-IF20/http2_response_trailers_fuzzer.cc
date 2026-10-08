// Exercise nginx's real HTTP/2 response-body send chain and trailer builder.
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_v2_fuzz_send_chain(u_char *data, size_t len);
}

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
    fuzz_log.log_level = NGX_LOG_EMERG;
    if (ngx_event_timer_init(&fuzz_log) != NGX_OK) {
        std::abort();
    }
    ngx_queue_init(&ngx_posted_events);
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
    if (size > 0 && size <= 65536) {
        ngx_int_t rc = ngx_http_v2_fuzz_send_chain(
            const_cast<u_char *>(data), size);

        if (size >= 4 && data[0] == 1 && data[1] >= 5 && data[1] <= 21
            && rc != NGX_OK
            && (data[1] != 17
                || (size == 5 && data[2] == 0 && data[3] == 0
                    && data[4] == 'A')))
        {
            std::abort();
        }
    }
    return 0;
}
