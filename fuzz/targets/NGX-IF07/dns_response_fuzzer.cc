// Stateful target for nginx's asynchronous DNS response parser.  The
// build-only hook prepares a matching pending query before parsing the packet.
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

void ngx_resolver_fuzz_process_response(ngx_resolver_t *r, u_char *buf,
                                        size_t n, ngx_uint_t mode);
}

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

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
    fuzz_log.log_level = NGX_LOG_EMERG;
    fuzz_cycle.log = &fuzz_log;
    fuzz_cycle.new_log = fuzz_log;
    ngx_cycle = &fuzz_cycle;
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int initialized = initialize_runtime();
    (void) initialized;

    if (size < 2) {
        return 0;
    }

    ngx_pool_t *pool = ngx_create_pool(4096, &fuzz_log);
    if (pool == nullptr) {
        std::abort();
    }

    fuzz_cycle.pool = pool;
    ngx_conf_t conf = {};
    conf.pool = pool;
    conf.cycle = &fuzz_cycle;
    conf.log = &fuzz_log;

    ngx_resolver_t *resolver = ngx_resolver_create(&conf, nullptr, 0);
    if (resolver == nullptr) {
        ngx_destroy_pool(pool);
        std::abort();
    }

    const size_t packet_size = size - 1;
    std::vector<u_char> packet(packet_size + 128, 0);
    std::memcpy(packet.data(), data + 1, packet_size);

    ngx_resolver_fuzz_process_response(resolver, packet.data(), packet_size,
                                       data[0]);

    ngx_destroy_pool(pool);
    fuzz_cycle.pool = nullptr;
    return 0;
}
