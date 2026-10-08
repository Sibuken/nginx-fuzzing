// Fuzz nginx's real HTTP/2 upstream trailer-frame parser.
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_proxy_v2_fuzz_trailers(u_char *data, size_t len,
    ngx_uint_t *trailer_count);
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

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
    fuzz_cycle.log = &fuzz_log;
    fuzz_cycle.new_log = fuzz_log;
    ngx_cycle = &fuzz_cycle;
    if (ngx_preinit_modules() != NGX_OK) {
        __builtin_trap();
    }
    fuzz_cycle.modules = ngx_modules;
    (void) ngx_count_modules(&fuzz_cycle, NGX_HTTP_MODULE);
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const bool initialized = (initialize_runtime(), true);
    (void) initialized;

    if (size > 0 && size <= 16384) {
        ngx_uint_t count = 0;
        ngx_int_t rc = ngx_http_proxy_v2_fuzz_trailers(
            const_cast<u_char *>(data), size, &count);

        static const uint8_t valid[] = { 0, 0, 1, 'x', 1, 'a' };
        static const uint8_t continued[] = { 1, 0, 1, 'x', 1, 'a' };
        static const uint8_t pseudo[] = {
            0, 0x10, 7, ':', 's', 't', 'a', 't', 'u', 's', 3, '2', '0', '0'
        };
        static const uint8_t no_end_stream[] = { 2, 0, 1, 'x', 1, 'a' };
        static const uint8_t invalid_index[] = { 0, 0xff };
        static const uint8_t data_preamble[] = {
            8, 'B', 0, 1, 'x', 1, 'a'
        };
        static const uint8_t data_continued[] = {
            9, 'B', 0, 1, 'x', 1, 'a'
        };
        static const uint8_t data_padded[] = {
            16, 'B', 1, 0, 1, 'x', 1, 'a'
        };
        static const uint8_t data_padded_zero[] = {
            16, 'B', 0, 0, 1, 'x', 1, 'a'
        };
        static const uint8_t data_bad_padding[] = {
            32, 'B', 0, 1, 'x', 1, 'a'
        };
        static const uint8_t two_data[] = {
            64, 'B', 'C', 0, 1, 'x', 1, 'a'
        };
        static const uint8_t padded_then_data[] = {
            80, 'B', 1, 'C', 0, 1, 'x', 1, 'a'
        };
        static const uint8_t data_then_padded[] = {
            96, 'B', 'C', 1, 0, 1, 'x', 1, 'a'
        };
        static const uint8_t end_stream_before_trailers[] = {
            128, 'B', 0, 1, 'x', 1, 'a'
        };
        static const uint8_t padded_end_stream_before_trailers[] = {
            144, 'B', 1, 0, 1, 'x', 1, 'a'
        };
        static const uint8_t data_after_end_stream[] = {
            136, 'B', 0xff, 'C'
        };

        if (size == sizeof(valid) && memcmp(data, valid, size) == 0
            && (rc != NGX_DONE || count != 1))
        {
            abort();
        }

        if (size == sizeof(continued)
            && memcmp(data, continued, size) == 0
            && (rc != NGX_DONE || count != 1))
        {
            abort();
        }

        if (size == sizeof(data_preamble)
            && memcmp(data, data_preamble, size) == 0
            && (rc != NGX_DONE || count != 1))
        {
            abort();
        }

        if (size == sizeof(data_continued)
            && memcmp(data, data_continued, size) == 0
            && (rc != NGX_DONE || count != 1))
        {
            abort();
        }

        if (size == sizeof(data_padded)
            && memcmp(data, data_padded, size) == 0
            && (rc != NGX_DONE || count != 1))
        {
            abort();
        }

        if (size == sizeof(data_padded_zero)
            && memcmp(data, data_padded_zero, size) == 0
            && (rc != NGX_DONE || count != 1))
        {
            abort();
        }

        if (size == sizeof(data_bad_padding)
            && memcmp(data, data_bad_padding, size) == 0
            && rc != NGX_ERROR)
        {
            abort();
        }

        if (size == sizeof(two_data) && memcmp(data, two_data, size) == 0
            && (rc != NGX_DONE || count != 1))
        {
            abort();
        }

        if (size == sizeof(padded_then_data)
            && memcmp(data, padded_then_data, size) == 0
            && (rc != NGX_DONE || count != 1))
        {
            abort();
        }

        if (size == sizeof(data_then_padded)
            && memcmp(data, data_then_padded, size) == 0
            && (rc != NGX_DONE || count != 1))
        {
            abort();
        }

        if (size == sizeof(end_stream_before_trailers)
            && memcmp(data, end_stream_before_trailers, size) == 0
            && rc != NGX_ERROR)
        {
            abort();
        }

        if (size == sizeof(padded_end_stream_before_trailers)
            && memcmp(data, padded_end_stream_before_trailers, size) == 0
            && rc != NGX_ERROR)
        {
            abort();
        }

        if (size == sizeof(data_after_end_stream)
            && memcmp(data, data_after_end_stream, size) == 0
            && rc != NGX_ERROR)
        {
            abort();
        }

        if (size == sizeof(pseudo) && memcmp(data, pseudo, size) == 0
            && rc != NGX_ERROR)
        {
            abort();
        }

        if (size == sizeof(no_end_stream)
            && memcmp(data, no_end_stream, size) == 0
            && rc != NGX_ERROR)
        {
            abort();
        }

        if (size == sizeof(invalid_index)
            && memcmp(data, invalid_index, size) == 0
            && rc != NGX_ERROR)
        {
            abort();
        }
    }

    return 0;
}
