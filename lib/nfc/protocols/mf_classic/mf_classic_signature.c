#include "mf_classic.h"

#include <mbedtls/ecdsa.h>

// NXP originality signature: ECDSA over secp128r1 of the raw UID (no hash), with r in
// block 69 and s in block 70 of the EV1 hidden sector 17
#define MF_CLASSIC_EV1_SIGNATURE_R_BLOCK (69)
#define MF_CLASSIC_EV1_SIGNATURE_S_BLOCK (70)

// secp128r1 domain parameters (SEC 2). Its a = p - 3, which mbedtls assumes when A is unset.
#define SECP128R1_P  "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF"
#define SECP128R1_B  "E87579C11079F43DD824993C2CEE5ED3"
#define SECP128R1_GX "161FF7528B899B2D0C28607CA52C5B86"
#define SECP128R1_GY "CF5AC8395BAFEB13C02DA292DDED7A83"
#define SECP128R1_N  "FFFFFFFE0000000075A30D1B9038A115"

// NXP public key for MIFARE Classic EV1 (MFC1C14_x)
#define MF_CLASSIC_NXP_PUBLIC_KEY_X "4F6D3F294DEA5737F0F46FFEE88A356E"
#define MF_CLASSIC_NXP_PUBLIC_KEY_Y "ED95695DD7E0C27A591E6F6F65962BAF"

static bool mf_classic_verify_signature(
    const uint8_t* uid,
    size_t uid_len,
    const MfClassicBlock* r_block,
    const MfClassicBlock* s_block) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    bool valid = false;
    do {
        if(mbedtls_mpi_read_string(&grp.P, 16, SECP128R1_P) != 0) break;
        if(mbedtls_mpi_read_string(&grp.B, 16, SECP128R1_B) != 0) break;
        if(mbedtls_mpi_read_string(&grp.N, 16, SECP128R1_N) != 0) break;
        if(mbedtls_ecp_point_read_string(&grp.G, 16, SECP128R1_GX, SECP128R1_GY) != 0) break;
        grp.pbits = mbedtls_mpi_bitlen(&grp.P);
        grp.nbits = mbedtls_mpi_bitlen(&grp.N);

        if(mbedtls_ecp_point_read_string(
               &q, 16, MF_CLASSIC_NXP_PUBLIC_KEY_X, MF_CLASSIC_NXP_PUBLIC_KEY_Y) != 0)
            break;
        if(mbedtls_mpi_read_binary(&r, r_block->data, MF_CLASSIC_BLOCK_SIZE) != 0) break;
        if(mbedtls_mpi_read_binary(&s, s_block->data, MF_CLASSIC_BLOCK_SIZE) != 0) break;

        valid = (mbedtls_ecdsa_verify(&grp, uid, uid_len, &q, &r, &s) == 0);
    } while(false);

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);

    return valid;
}

MfClassicSignatureStatus mf_classic_get_signature_status(const MfClassicData* data) {
    furi_check(data);

    if(data->type != MfClassicType1kEv1) return MfClassicSignatureStatusNotAvailable;
    if(!mf_classic_is_block_read(data, MF_CLASSIC_EV1_SIGNATURE_R_BLOCK) ||
       !mf_classic_is_block_read(data, MF_CLASSIC_EV1_SIGNATURE_S_BLOCK)) {
        return MfClassicSignatureStatusNotAvailable;
    }

    size_t uid_len = 0;
    const uint8_t* uid = mf_classic_get_uid(data, &uid_len);

    return mf_classic_verify_signature(
               uid,
               uid_len,
               &data->block[MF_CLASSIC_EV1_SIGNATURE_R_BLOCK],
               &data->block[MF_CLASSIC_EV1_SIGNATURE_S_BLOCK]) ?
               MfClassicSignatureStatusValid :
               MfClassicSignatureStatusInvalid;
}
