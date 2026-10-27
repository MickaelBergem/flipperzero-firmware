#pragma once

#include "mf_classic.h"

#ifdef __cplusplus
extern "C" {
#endif

// Records the frames a reader sends to the emulated card, decrypted, with what the
// emulation answered. Recording only fills a RAM buffer, and stops once it is full
// to keep the start of the exchange. The text is written by
// mf_classic_trace_save() once the emulation is stopped.

// The buffer grows while recording, up to capacity, as long as the free heap keeps a
// margin. Returns the capacity available at start, 0 when there is no memory left.
size_t mf_classic_trace_start(size_t capacity);

void mf_classic_trace_stop(void);

bool mf_classic_trace_save(const char* path, const MfClassicData* data);

#ifdef __cplusplus
}
#endif
