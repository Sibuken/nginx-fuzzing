// Stateful target for HTTP/2 DATA frames. The isolated build-only driver
// provides a minimal request and preread buffer for one live stream.
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

    if (ngx_event_timer_init(&fuzz_log) != NGX_OK) {
        std::abort();
    }

    return 0;
}

static void
run_fragmentation(const uint8_t *data, size_t size, size_t chunk,
    ngx_uint_t data_mode)
{
    ngx_pool_t *pool = ngx_create_pool(4096, &fuzz_log);
    if (pool == nullptr) {
        std::abort();
    }

    (void) ngx_http_v2_fuzz_control_frames(
        pool, &fuzz_log, const_cast<u_char *>(data), size, chunk, 0, 0, 1,
        data_mode);

    ngx_destroy_pool(pool);
}

static bool
valid_data_sequence(const uint8_t *data, size_t size)
{
    size_t offset = 0;
    size_t frames = 0;
    size_t body_size = 0;
    bool ended = false;

    while (offset < size) {
        if (size - offset < 9 || data[offset + 3] != 0
            || (data[offset + 4] & 0xfe) != 0
            || data[offset + 5] != 0 || data[offset + 6] != 0
            || data[offset + 7] != 0 || data[offset + 8] != 1)
        {
            return false;
        }

        uint8_t flags = data[offset + 4];
        size_t frame_size = ((size_t) data[offset] << 16)
                            | ((size_t) data[offset + 1] << 8)
                            | data[offset + 2];
        offset += 9;

        if (frame_size > size - offset) {
            return false;
        }

        body_size += frame_size;
        offset += frame_size;
        frames++;

        if (flags & 1) {
            if (offset != size) {
                return false;
            }
            ended = true;
        } else if (offset == size) {
            return false;
        }
    }

    return frames >= 2 && ended && body_size > 16;
}

static bool
valid_padded_data_sequence(const uint8_t *data, size_t size)
{
    size_t offset = 0;
    size_t frames = 0;
    size_t body_size = 0;
    bool ended = false;

    while (offset < size) {
        if (size - offset < 10 || data[offset + 3] != 0
            || (data[offset + 4] & 0xf6) != 0
            || (data[offset + 4] & 0x08) == 0
            || data[offset + 5] != 0 || data[offset + 6] != 0
            || data[offset + 7] != 0 || data[offset + 8] != 1)
        {
            return false;
        }

        uint8_t flags = data[offset + 4];
        size_t frame_size = ((size_t) data[offset] << 16)
                            | ((size_t) data[offset + 1] << 8)
                            | data[offset + 2];
        offset += 9;

        if (frame_size > size - offset || frame_size < 2
            || data[offset] >= frame_size)
        {
            return false;
        }

        body_size += frame_size - 1 - data[offset];
        offset += frame_size;
        frames++;

        if (flags & 1) {
            if (offset != size) {
                return false;
            }
            ended = true;
        } else if (offset == size) {
            return false;
        }
    }

    return frames >= 2 && ended && body_size > 16;
}

static bool
valid_mixed_padding_sequence(const uint8_t *data, size_t size)
{
    size_t offset = 0;
    size_t frames = 0;
    size_t body_size = 0;
    bool saw_padded = false;
    bool saw_unpadded = false;
    bool ended = false;

    while (offset < size) {
        if (size - offset < 9 || data[offset + 3] != 0
            || (data[offset + 4] & 0xf6) != 0
            || data[offset + 5] != 0 || data[offset + 6] != 0
            || data[offset + 7] != 0 || data[offset + 8] != 1)
        {
            return false;
        }

        uint8_t flags = data[offset + 4];
        size_t frame_size = ((size_t) data[offset] << 16)
                            | ((size_t) data[offset + 1] << 8)
                            | data[offset + 2];
        offset += 9;

        if (frame_size > size - offset) {
            return false;
        }

        if (flags & 0x08) {
            if (frame_size < 2 || data[offset] >= frame_size) {
                return false;
            }
            body_size += frame_size - 1 - data[offset];
            saw_padded = true;
        } else {
            body_size += frame_size;
            saw_unpadded = true;
        }

        offset += frame_size;
        frames++;

        if (flags & 1) {
            if (offset != size) {
                return false;
            }
            ended = true;
        } else if (offset == size) {
            return false;
        }
    }

    return frames >= 2 && ended && saw_padded && saw_unpadded
           && body_size > 16;
}

static bool
valid_long_alternating_padding_sequence(const uint8_t *data, size_t size)
{
    if (!valid_mixed_padding_sequence(data, size)) {
        return false;
    }

    size_t offset = 0;
    size_t frames = 0;
    size_t body_size = 0;
    size_t transitions = 0;
    bool previous_padded = false;
    bool have_previous = false;

    while (offset < size) {
        uint8_t flags = data[offset + 4];
        bool padded = (flags & 0x08) != 0;
        size_t frame_size = ((size_t) data[offset] << 16)
                            | ((size_t) data[offset + 1] << 8)
                            | data[offset + 2];
        offset += 9;

        if (padded) {
            body_size += frame_size - 1 - data[offset];
        } else {
            body_size += frame_size;
        }

        if (have_previous && padded != previous_padded) {
            transitions++;
        }

        previous_padded = padded;
        have_previous = true;
        frames++;
        offset += frame_size;
    }

    return frames >= 6 && transitions >= 5 && body_size >= 48;
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
    uint32_t payload_size;

    run_fragmentation(data, size, size == 0 ? 1 : size, 0);
    run_fragmentation(data, size, 1, 0);
    run_fragmentation(data, size, 3, 0);
    run_fragmentation(data, size, selected, 0);
    run_fragmentation(data, size, size == 0 ? 1 : size, 1);
    run_fragmentation(data, size, 1, 1);
    run_fragmentation(data, size, 3, 1);
    run_fragmentation(data, size, selected, 1);
    if (size > 25
        && data[3] == 0
        && (data[4] & 0xfe) == 0
        && data[5] == 0 && data[6] == 0 && data[7] == 0 && data[8] == 1)
    {
        payload_size = ((uint32_t) data[0] << 16)
                       | ((uint32_t) data[1] << 8) | data[2];

        if (payload_size == size - 9) {
            run_fragmentation(data, size, size, 2);
            run_fragmentation(data, size, size, 4);
            run_fragmentation(data, size, size, 5);
            if ((data[4] & 1) != 0) {
                run_fragmentation(data, size, size, 6);
            }
        }
    }

    if (size > 25
        && data[3] == 0
        && (data[4] & 0xf6) == 0
        && (data[4] & 0x09) == 0x09
        && data[5] == 0 && data[6] == 0 && data[7] == 0 && data[8] == 1)
    {
        payload_size = ((uint32_t) data[0] << 16)
                       | ((uint32_t) data[1] << 8) | data[2];

        if (payload_size == size - 9
            && data[9] < payload_size
            && payload_size - 1 - data[9] > 16)
        {
            run_fragmentation(data, size, size, 7);
            run_fragmentation(data, size, 1, 7);
            run_fragmentation(data, size, 3, 7);
            run_fragmentation(data, size, selected, 7);
        }
    }

    if (size <= 4096 && valid_data_sequence(data, size)) {
        run_fragmentation(data, size, size, 3);
    }

    if (size <= 4096 && valid_padded_data_sequence(data, size)) {
        run_fragmentation(data, size, size, 8);
        run_fragmentation(data, size, 1, 8);
        run_fragmentation(data, size, 3, 8);
        run_fragmentation(data, size, selected, 8);
    }

    if (size <= 4096 && valid_mixed_padding_sequence(data, size)) {
        run_fragmentation(data, size, size, 9);
        run_fragmentation(data, size, 1, 9);
        run_fragmentation(data, size, 3, 9);
        run_fragmentation(data, size, selected, 9);
    }

    if (size <= 4096
        && valid_long_alternating_padding_sequence(data, size))
    {
        run_fragmentation(data, size, size, 10);
        run_fragmentation(data, size, 1, 10);
        run_fragmentation(data, size, 3, 10);
        run_fragmentation(data, size, selected, 10);
    }

    return 0;
}
