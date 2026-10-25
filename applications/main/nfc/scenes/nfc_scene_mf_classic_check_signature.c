#include "../nfc_app_i.h"

void nfc_scene_mf_classic_check_signature_on_enter(void* context) {
    NfcApp* instance = context;

    // Verification takes over a second: keep the loading animation running meanwhile
    nfc_show_loading_popup(instance, true);
    const MfClassicData* data = nfc_device_get_data(instance->nfc_device, NfcProtocolMfClassic);
    MfClassicSignatureStatus status = mf_classic_get_signature_status(data);
    nfc_show_loading_popup(instance, false);

    const char* header = "Signature Not Read";
    const char* text = "Read hidden sector 17\nto check the signature";
    if(status == MfClassicSignatureStatusValid) {
        header = "Signature Valid";
        text = "The card UID was\nsigned by NXP";
    } else if(status == MfClassicSignatureStatusInvalid) {
        header = "Signature Invalid";
        text = "The card UID was\nnot signed by NXP";
    }

    widget_add_string_element(instance->widget, 64, 5, AlignCenter, AlignTop, FontPrimary, header);
    widget_add_string_multiline_element(
        instance->widget, 64, 24, AlignCenter, AlignTop, FontSecondary, text);
    view_dispatcher_switch_to_view(instance->view_dispatcher, NfcViewWidget);
}

bool nfc_scene_mf_classic_check_signature_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void nfc_scene_mf_classic_check_signature_on_exit(void* context) {
    NfcApp* instance = context;

    widget_reset(instance->widget);
}
