#include "mf_classic_trace_i.h"

#include <furi.h>
#include <furi_hal.h>
#include <storage/storage.h>

#define MF_CLASSIC_TRACE_DATA_SIZE   (18) // Write data: 16 bytes + CRC
#define MF_CLASSIC_TRACE_HEAP_MARGIN (4096)
#define MF_CLASSIC_TRACE_CHUNK_SIZE  (32) // Entries per allocation
#define MF_CLASSIC_TRACE_CHUNKS_MAX  (32)

struct MfClassicTraceEntry {
    uint32_t tick;
    uint32_t cycles;
    uint16_t bits;
    uint8_t event;
    uint8_t flags;
    uint8_t result;
    uint8_t data[MF_CLASSIC_TRACE_DATA_SIZE];
};

// Allocated in small chunks: the NFC app heap is too fragmented for one large buffer
static struct {
    MfClassicTraceEntry* chunks[MF_CLASSIC_TRACE_CHUNKS_MAX];
    size_t chunks_num;
    size_t capacity;
    size_t max_capacity;
    size_t count;
    size_t skipped;
    size_t heap_free_at_start;
    size_t heap_max_block_at_start;
} mf_classic_trace = {};

static MfClassicTraceEntry* mf_classic_trace_get_entry(size_t index) {
    return &mf_classic_trace
                .chunks[index / MF_CLASSIC_TRACE_CHUNK_SIZE][index % MF_CLASSIC_TRACE_CHUNK_SIZE];
}

// Adds one chunk if the heap keeps the margin after it
static bool mf_classic_trace_grow(void) {
    const size_t chunk_bytes = MF_CLASSIC_TRACE_CHUNK_SIZE * sizeof(MfClassicTraceEntry);
    if(mf_classic_trace.capacity >= mf_classic_trace.max_capacity) return false;
    if(memmgr_get_free_heap() < MF_CLASSIC_TRACE_HEAP_MARGIN + chunk_bytes) return false;
    if(memmgr_heap_get_max_free_block() < chunk_bytes) return false;

    mf_classic_trace.chunks[mf_classic_trace.chunks_num++] = malloc(chunk_bytes);
    mf_classic_trace.capacity += MF_CLASSIC_TRACE_CHUNK_SIZE;
    return true;
}

size_t mf_classic_trace_start(size_t capacity) {
    furi_check(mf_classic_trace.max_capacity == 0);

    // Chunks are added while recording: the heap often has more room once the emulation
    // scene is set up than when it starts
    mf_classic_trace.max_capacity =
        MIN(capacity, (size_t)MF_CLASSIC_TRACE_CHUNKS_MAX * MF_CLASSIC_TRACE_CHUNK_SIZE);
    mf_classic_trace.heap_free_at_start = memmgr_get_free_heap();
    mf_classic_trace.heap_max_block_at_start = memmgr_heap_get_max_free_block();
    mf_classic_trace_grow();

    return mf_classic_trace.capacity;
}

void mf_classic_trace_stop(void) {
    for(size_t i = 0; i < mf_classic_trace.chunks_num; i++) {
        free(mf_classic_trace.chunks[i]);
    }
    memset(&mf_classic_trace, 0, sizeof(mf_classic_trace));
}

MfClassicTraceEntry*
    mf_classic_trace_add(MfClassicTraceEvent event, const BitBuffer* frame, uint8_t flags) {
    if(mf_classic_trace.max_capacity == 0) return NULL;

    // Keep the start of the exchange: once the buffer cannot grow, later frames are only counted
    if(mf_classic_trace.count == mf_classic_trace.capacity && !mf_classic_trace_grow()) {
        mf_classic_trace.skipped++;
        return NULL;
    }

    MfClassicTraceEntry* entry = mf_classic_trace_get_entry(mf_classic_trace.count);
    mf_classic_trace.count++;

    entry->tick = furi_get_tick();
    entry->cycles = DWT->CYCCNT;
    entry->event = event;
    entry->flags = flags;
    entry->result = MfClassicTraceResultNone;
    entry->bits = 0;
    if(frame) {
        entry->bits = bit_buffer_get_size(frame);
        size_t bytes = MIN(bit_buffer_get_size_bytes(frame), sizeof(entry->data));
        for(size_t i = 0; i < bytes; i++) {
            entry->data[i] = bit_buffer_get_byte(frame, i);
        }
    }

    return entry;
}

void mf_classic_trace_set_result(
    MfClassicTraceEntry* entry,
    MfClassicTraceResult result,
    uint8_t flags) {
    if(entry == NULL) return;

    entry->result = result;
    entry->flags |= flags;
}

static bool mf_classic_trace_is_auth(uint8_t cmd) {
    return cmd == MF_CLASSIC_CMD_AUTH_KEY_A || cmd == MF_CLASSIC_CMD_AUTH_KEY_B ||
           cmd == MF_CLASSIC_CMD_BACKDOOR_AUTH_KEY_A || cmd == MF_CLASSIC_CMD_BACKDOOR_AUTH_KEY_B;
}

static void mf_classic_trace_describe_frame(
    FuriString* str,
    const MfClassicTraceEntry* entry,
    uint8_t last_cmd) {
    if(entry->flags & MF_CLASSIC_TRACE_FLAG_CONTINUATION) {
        if(mf_classic_trace_is_auth(last_cmd)) {
            furi_string_cat(str, "AUTH part 2 (reader nonce and answer)");
        } else if(last_cmd == MF_CLASSIC_CMD_WRITE_BLOCK) {
            furi_string_cat(str, "WRITE data");
        } else {
            furi_string_cat(str, "VALUE operand");
        }
        return;
    }

    if(entry->bits < 8) {
        furi_string_cat_printf(str, "short frame (%u bits)", entry->bits);
        return;
    }

    uint8_t cmd = entry->data[0];
    uint8_t block = entry->bits >= 16 ? entry->data[1] : 0;
    uint8_t sector = mf_classic_get_sector_by_block(block);

    switch(cmd) {
    case MF_CLASSIC_CMD_AUTH_KEY_A:
    case MF_CLASSIC_CMD_AUTH_KEY_B:
        furi_string_cat_printf(
            str,
            "AUTH key %c, block %u (sector %u)",
            cmd == MF_CLASSIC_CMD_AUTH_KEY_A ? 'A' : 'B',
            block,
            sector);
        break;
    case MF_CLASSIC_CMD_BACKDOOR_AUTH_KEY_A:
    case MF_CLASSIC_CMD_BACKDOOR_AUTH_KEY_B:
        furi_string_cat_printf(str, "backdoor AUTH, block %u (sector %u)", block, sector);
        break;
    case MF_CLASSIC_CMD_READ_BLOCK:
        furi_string_cat_printf(str, "READ block %u (sector %u)", block, sector);
        break;
    case MF_CLASSIC_CMD_WRITE_BLOCK:
        furi_string_cat_printf(str, "WRITE block %u (sector %u)", block, sector);
        break;
    case MF_CLASSIC_CMD_VALUE_DEC:
        furi_string_cat_printf(str, "DECREMENT block %u", block);
        break;
    case MF_CLASSIC_CMD_VALUE_INC:
        furi_string_cat_printf(str, "INCREMENT block %u", block);
        break;
    case MF_CLASSIC_CMD_VALUE_RESTORE:
        furi_string_cat_printf(str, "RESTORE block %u", block);
        break;
    case MF_CLASSIC_CMD_VALUE_TRANSFER:
        furi_string_cat_printf(str, "TRANSFER to block %u", block);
        break;
    case MF_CLASSIC_CMD_HALT_MSB:
        furi_string_cat(str, "HALT");
        break;
    case 0x40:
        furi_string_cat(str, "PERSONALIZE UID USAGE (EV1)");
        break;
    case 0x43:
        furi_string_cat(str, "SET_MOD_TYPE (EV1)");
        break;
    case 0xE0:
        furi_string_cat(str, "RATS (ISO 14443-4)");
        break;
    default:
        furi_string_cat_printf(str, "unknown command 0x%02X", cmd);
        break;
    }
}

static const char*
    mf_classic_trace_describe_result(const MfClassicTraceEntry* entry, uint8_t last_cmd) {
    switch(entry->result) {
    case MfClassicTraceResultAnswered:
        return "answered";
    case MfClassicTraceResultAck:
        return "ACK";
    case MfClassicTraceResultNack:
        return (entry->flags & MF_CLASSIC_TRACE_FLAG_UNSUPPORTED) ? "NACK (unsupported command)" :
                                                                    "NACK";
    case MfClassicTraceResultSilent:
        return "no answer";
    case MfClassicTraceResultSleep:
        return ((entry->flags & MF_CLASSIC_TRACE_FLAG_CONTINUATION) &&
                mf_classic_trace_is_auth(last_cmd)) ?
                   "no answer (reader used another key)" :
                   "no answer, card back to idle";
    default:
        return "";
    }
}

static bool mf_classic_trace_write(File* file, FuriString* str) {
    size_t size = furi_string_size(str);
    return storage_file_write(file, furi_string_get_cstr(str), size) == size;
}

bool mf_classic_trace_save(const char* path, const MfClassicData* data) {
    furi_check(path);
    furi_check(data);

    if(mf_classic_trace.max_capacity == 0) return false;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    FuriString* line = furi_string_alloc();
    bool success = false;

    do {
        if(!storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) break;

        size_t uid_len = 0;
        const uint8_t* uid = mf_classic_get_uid(data, &uid_len);
        furi_string_printf(
            line,
            "# MIFARE Classic emulation trace\n# Card: %s, UID",
            mf_classic_get_device_name(data, NfcDeviceNameTypeFull));
        for(size_t i = 0; i < uid_len; i++) {
            furi_string_cat_printf(line, " %02X", uid[i]);
        }
        furi_string_cat_printf(
            line,
            "\n# Entries: %zu recorded, %zu more not recorded (buffer full at %zu of %zu)\n"
            "# Free heap at start: %zu bytes, largest block %zu\n"
            "# Time since the first entry. RDR: frame from the reader, [dec]: received encrypted,\n"
            "# shown decrypted. After the arrow: what the emulated card did.\n\n",
            mf_classic_trace.count,
            mf_classic_trace.skipped,
            mf_classic_trace.capacity,
            mf_classic_trace.max_capacity,
            mf_classic_trace.heap_free_at_start,
            mf_classic_trace.heap_max_block_at_start);
        if(!mf_classic_trace_write(file, line)) break;

        uint32_t cycles_per_us = furi_hal_cortex_instructions_per_microsecond();
        uint64_t elapsed_us = 0;
        uint8_t last_cmd = 0;
        const MfClassicTraceEntry* prev = NULL;
        bool written = true;

        for(size_t i = 0; i < mf_classic_trace.count; i++) {
            const MfClassicTraceEntry* entry = mf_classic_trace_get_entry(i);
            if(prev) {
                // The cycle counter wraps every minute, use the tick for longer gaps
                uint32_t tick_delta = entry->tick - prev->tick;
                elapsed_us += tick_delta > 30000 ? (uint64_t)tick_delta * 1000 :
                                                   (entry->cycles - prev->cycles) / cycles_per_us;
            }
            prev = entry;

            furi_string_printf(
                line,
                "%7lu.%03lu ms  ",
                (uint32_t)(elapsed_us / 1000),
                (uint32_t)(elapsed_us % 1000));

            if(entry->event == MfClassicTraceEventFieldOff) {
                furi_string_cat(line, "--- field off (card removed or reader reset)\n");
            } else if(entry->event == MfClassicTraceEventHalted) {
                furi_string_cat(line, "--- HALT (card idle until woken up)\n");
            } else {
                furi_string_cat(
                    line,
                    (entry->flags & MF_CLASSIC_TRACE_FLAG_DECRYPTED) ? "RDR [dec] " :
                                                                       "RDR       ");

                size_t bytes = MIN((size_t)(entry->bits + 7) / 8, sizeof(entry->data));
                size_t hex_start = furi_string_size(line);
                for(size_t j = 0; j < bytes; j++) {
                    furi_string_cat_printf(line, "%02X ", entry->data[j]);
                }
                while(furi_string_size(line) < hex_start + 24) {
                    furi_string_push_back(line, ' ');
                }

                mf_classic_trace_describe_frame(line, entry, last_cmd);
                furi_string_cat_printf(
                    line, "  -> %s\n", mf_classic_trace_describe_result(entry, last_cmd));

                if(!(entry->flags & MF_CLASSIC_TRACE_FLAG_CONTINUATION) && entry->bits >= 8) {
                    last_cmd = entry->data[0];
                }
            }

            if(!mf_classic_trace_write(file, line)) {
                written = false;
                break;
            }
        }

        if(written && mf_classic_trace.skipped) {
            furi_string_printf(
                line,
                "--- buffer full: %zu more entries not recorded\n",
                mf_classic_trace.skipped);
            written = mf_classic_trace_write(file, line);
        }

        success = written;
    } while(false);

    furi_string_free(line);
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);

    return success;
}
