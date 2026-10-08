// Direct target for nginx's configuration tokenizer and command-line
// parameter parser.  The build-only wrapper exposes the otherwise static
// ngx_conf_read_token() without changing its implementation.
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>

ngx_int_t ngx_conf_fuzz_read_token(ngx_conf_t *cf);
}

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

static ngx_log_t fuzz_log;
static ngx_open_file_t fuzz_log_file;
static ngx_cycle_t fuzz_cycle;
static volatile u_char fuzz_sink;

static int
initialize_runtime()
{
    ngx_time_init();
    ngx_strerror_init();

    fuzz_log_file.fd = ngx_stderr;
    fuzz_log.file = &fuzz_log_file;
    // Malformed configuration is normal fuzz input.  Keep parser return codes
    // observable without formatting an emergency log line for every mutation.
    fuzz_log.log_level = 0;
    fuzz_cycle.log = &fuzz_log;
    fuzz_cycle.new_log = fuzz_log;
    ngx_cycle = &fuzz_cycle;
    return 0;
}

static void
consume_args(ngx_conf_t *cf)
{
    ngx_str_t *value = static_cast<ngx_str_t *>(cf->args->elts);

    for (ngx_uint_t i = 0; i < cf->args->nelts; i++) {
        fuzz_sink ^= static_cast<u_char>(value[i].len);
        if (value[i].len != 0) {
            fuzz_sink ^= value[i].data[0];
            fuzz_sink ^= value[i].data[value[i].len - 1];
        }
    }
}

static char *
accept_directive(ngx_conf_t *cf, ngx_command_t *, void *)
{
    consume_args(cf);
    return NGX_CONF_OK;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int initialized = initialize_runtime();
    (void) initialized;

    ngx_pool_t *pool = ngx_create_pool(4096, &fuzz_log);
    if (pool == nullptr) {
        std::abort();
    }

    u_char *input = static_cast<u_char *>(ngx_pnalloc(pool, size + 1));
    if (input == nullptr) {
        ngx_destroy_pool(pool);
        std::abort();
    }
    if (size != 0) {
        std::memcpy(input, data, size);
    }
    input[size] = '\0';

    fuzz_cycle.pool = pool;
    fuzz_cycle.conf_param.data = input;
    fuzz_cycle.conf_param.len = size;

    ngx_conf_t conf = {};
    conf.args = ngx_array_create(pool, 4, sizeof(ngx_str_t));
    if (conf.args == nullptr) {
        ngx_destroy_pool(pool);
        std::abort();
    }
    conf.cycle = &fuzz_cycle;
    conf.pool = pool;
    conf.temp_pool = pool;
    conf.log = &fuzz_log;

    ngx_buf_t buffer = {};
    buffer.start = input;
    buffer.pos = input;
    buffer.last = input + size;
    buffer.end = buffer.last;
    buffer.temporary = 1;

    ngx_conf_file_t conf_file = {};
    conf_file.file.fd = NGX_INVALID_FILE;
    conf_file.buffer = &buffer;
    conf_file.line = 1;
    conf.conf_file = &conf_file;

    for (size_t calls = 0; calls <= size + 1; calls++) {
        u_char *before = buffer.pos;
        ngx_int_t rc = ngx_conf_fuzz_read_token(&conf);
        consume_args(&conf);

        if (rc == NGX_ERROR || rc == NGX_CONF_FILE_DONE) {
            break;
        }
        if (rc != NGX_OK && rc != NGX_CONF_BLOCK_START
            && rc != NGX_CONF_BLOCK_DONE)
        {
            __builtin_trap();
        }
        if (buffer.pos <= before) {
            __builtin_trap();
        }
    }

    conf.conf_file = nullptr;
    conf.handler = accept_directive;
    (void) ngx_conf_param(&conf);

    fuzz_cycle.conf_param.data = nullptr;
    fuzz_cycle.conf_param.len = 0;
    fuzz_cycle.pool = nullptr;
    ngx_destroy_pool(pool);
    return 0;
}
