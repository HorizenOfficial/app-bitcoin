#include "sign_message_helpers.h"
#include "btchip_apdu_constants.h"
#include "read.h"
#include "btchip_internal.h"
#include "btchip_apdu_constants.h"
#include "btchip_bagl_extensions.h"

unsigned char message_check_bit_id(unsigned char *bip32Path) {
    unsigned char i;
    unsigned char bip32PathLength = bip32Path[0];
    bip32Path++;
    for (i = 0; i < bip32PathLength; i++) {
        unsigned short account = read_u32_be(bip32Path, 0);
        bip32Path += 4;

        if (account == BITID_DERIVE) {
            return BITID_POWERCYCLE;
        }
        if (account == BITID_DERIVE_MULTIPLE) {
            return BITID_MULTIPLE;
        }
    }
    return BITID_NONE;
}

unsigned short message_compute_hash(void) {
    unsigned char hash[32];
    unsigned short sw = BTCHIP_SW_OK;

    btchip_context_D.outLength = 0;
    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.sha256.header, CX_LAST, hash,
                0, hash, 32)) {
        goto discard;
    }
            
    if (cx_hash_sha256(hash, sizeof(hash), hash, 32) == 0) {
        goto discard;
    }

    size_t out_len = 100;
    btchip_sign_finalhash(
            btchip_context_D.transactionSummary.keyPath,
            sizeof(btchip_context_D.transactionSummary.keyPath),
            hash, sizeof(hash), // IN
            G_io_apdu_buffer, &out_len);                        // OUT
    btchip_context_D.outLength = G_io_apdu_buffer[1] + 2;
            memset(&btchip_context_D.transactionSummary, 0,
                      sizeof(btchip_transaction_summary_t));
    return sw;

    discard: 
            sw = SW_TECHNICAL_DETAILS(0x0F);
            return sw;
}

