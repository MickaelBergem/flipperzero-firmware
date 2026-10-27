#pragma once

#include "../nfc_protocol_support_base.h"

extern const NfcProtocolSupportBase nfc_protocol_support_mf_classic;

// Saves the emulation trace started from "Emulate-trace", once the listener is stopped
void nfc_mf_classic_emulate_trace_finish(NfcApp* instance);
