#pragma once

#include "mf_classic_trace.h"

#include <toolbox/bit_buffer.h>

typedef enum {
    MfClassicTraceEventFrame,
    MfClassicTraceEventFieldOff,
    MfClassicTraceEventHalted,
} MfClassicTraceEvent;

typedef enum {
    MfClassicTraceResultNone,
    MfClassicTraceResultAnswered,
    MfClassicTraceResultAck,
    MfClassicTraceResultNack,
    MfClassicTraceResultSilent,
    MfClassicTraceResultSleep,
} MfClassicTraceResult;

#define MF_CLASSIC_TRACE_FLAG_DECRYPTED    (1U << 0)
#define MF_CLASSIC_TRACE_FLAG_CONTINUATION (1U << 1)
#define MF_CLASSIC_TRACE_FLAG_UNSUPPORTED  (1U << 2)

typedef struct MfClassicTraceEntry MfClassicTraceEntry;

// Both are no-ops when no trace is started. Called from the listener, keep them cheap.
MfClassicTraceEntry*
    mf_classic_trace_add(MfClassicTraceEvent event, const BitBuffer* frame, uint8_t flags);

void mf_classic_trace_set_result(
    MfClassicTraceEntry* entry,
    MfClassicTraceResult result,
    uint8_t flags);
