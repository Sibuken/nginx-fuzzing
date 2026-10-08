// Narrow follow-up target for the PROXY protocol parser. This file is local
// infrastructure; nginx production sources are not changed.
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
}

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

static ngx_log_t fuzz_log;
static ngx_open_file_t fuzz_log_file;

static int
initialize_runtime()
{
    ngx_time_init();
    ngx_strerror_init();
    fuzz_log_file.fd = ngx_stderr;
    fuzz_log.file = &fuzz_log_file;
    fuzz_log.log_level = NGX_LOG_EMERG;
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int initialized = initialize_runtime();
    (void) initialized;

    ngx_connection_t connection = {};
    connection.log = &fuzz_log;
    connection.pool = ngx_create_pool(1024, &fuzz_log);
    if (connection.pool == nullptr) {
        abort();
    }

    u_char *buffer = static_cast<u_char *>(
        ngx_pnalloc(connection.pool, size == 0 ? 1 : size));
    if (buffer == nullptr) {
        ngx_destroy_pool(connection.pool);
        abort();
    }
    if (size != 0) {
        memcpy(buffer, data, size);
    }

    u_char *result = ngx_proxy_protocol_read(&connection, buffer,
                                              buffer + size);
    if (result != nullptr && (result < buffer || result > buffer + size)) {
        __builtin_trap();
    }

    ngx_destroy_pool(connection.pool);
    return 0;
}
