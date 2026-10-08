// Follow-up target for PROXY protocol v2 TLV lookup.  It parses a complete
// header first, then queries every public named TLV and one input-selected
// numeric type through nginx's real accessor.
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
static volatile uint8_t fuzz_sink;

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

static void
lookup(ngx_connection_t *connection, const char *text)
{
    ngx_str_t name = {std::strlen(text),
                      reinterpret_cast<u_char *>(const_cast<char *>(text))};
    ngx_str_t value = ngx_null_string;
    ngx_int_t rc = ngx_proxy_protocol_get_tlv(connection, &name, &value);

    if (rc != NGX_OK && rc != NGX_DECLINED && rc != NGX_ERROR) {
        __builtin_trap();
    }

    if (rc == NGX_OK) {
        for (size_t i = 0; i < value.len; i++) {
            fuzz_sink ^= value.data[i];
        }
    }
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int initialized = initialize_runtime();
    (void) initialized;

    if (size < 2) {
        return 0;
    }

    ngx_connection_t connection = {};
    connection.log = &fuzz_log;
    connection.pool = ngx_create_pool(2048, &fuzz_log);
    if (connection.pool == nullptr) {
        std::abort();
    }

    size_t packet_size = size - 1;
    u_char *packet = static_cast<u_char *>(
        ngx_pnalloc(connection.pool, packet_size));
    if (packet == nullptr) {
        ngx_destroy_pool(connection.pool);
        std::abort();
    }
    std::memcpy(packet, data + 1, packet_size);

    u_char *end = ngx_proxy_protocol_read(&connection, packet,
                                           packet + packet_size);
    if (end != nullptr && (end < packet || end > packet + packet_size)) {
        __builtin_trap();
    }

    lookup(&connection, "alpn");

    if (connection.proxy_protocol != nullptr) {
        static const char *const names[] = {
            "authority", "unique_id", "ssl", "netns", "ssl_verify",
            "ssl_version", "ssl_cn", "ssl_cipher", "ssl_sig_alg",
            "ssl_key_alg", "missing"
        };

        for (const char *name : names) {
            lookup(&connection, name);
        }

        static const char hex[] = "0123456789abcdef";
        char numeric[] = "0x00";
        numeric[2] = hex[data[0] >> 4];
        numeric[3] = hex[data[0] & 0x0f];
        lookup(&connection, numeric);
    }

    ngx_destroy_pool(connection.pool);
    return 0;
}
