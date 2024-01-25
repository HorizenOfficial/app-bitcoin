/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

unsigned char const SIGNMAGIC[] = {' ', 'S', 'i', 'g', 'n', 'e', 'd', ' ', 'M',
                                   'e', 's', 's', 'a', 'g', 'e', ':', '\n'};

unsigned char const OVERWINTER_PARAM_PREVOUTS[16] = { 'Z', 'c', 'a', 's', 'h', 'P', 'r', 'e', 'v', 'o', 'u', 't', 'H', 'a', 's', 'h' };
unsigned char const OVERWINTER_PARAM_SEQUENCE[16] = { 'Z', 'c', 'a', 's', 'h', 'S', 'e', 'q', 'u', 'e', 'n', 'c', 'H', 'a', 's', 'h' };
unsigned char const OVERWINTER_PARAM_OUTPUTS[16] = { 'Z', 'c', 'a', 's', 'h', 'O', 'u', 't', 'p', 'u', 't', 's', 'H', 'a', 's', 'h' };
unsigned char const OVERWINTER_PARAM_SIGHASH[16] = { 'Z', 'c', 'a', 's', 'h', 'S', 'i', 'g', 'H', 'a', 's', 'h', 0, 0, 0, 0 };
unsigned char const OVERWINTER_NO_JOINSPLITS[32] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

unsigned char const DISPATCHER_CLA[] = {
    BTCHIP_CLA, // btchip_apdu_get_wallet_public_key,
    BTCHIP_CLA, // btchip_apdu_get_trusted_input,
    BTCHIP_CLA, // btchip_apdu_hash_input_start,
    BTCHIP_CLA, // btchip_apdu_hash_sign,
    BTCHIP_CLA, // btchip_apdu_hash_input_finalize_full,
    BTCHIP_CLA, // btchip_apdu_sign_message,
    BTCHIP_CLA, // btchip_apdu_get_coin_version
};

unsigned char const DISPATCHER_INS[] = {
    BTCHIP_INS_GET_WALLET_PUBLIC_KEY,    // btchip_apdu_get_wallet_public_key,
    BTCHIP_INS_GET_TRUSTED_INPUT,        // btchip_apdu_get_trusted_input,
    BTCHIP_INS_HASH_INPUT_START,         // btchip_apdu_hash_input_start,
    BTCHIP_INS_HASH_SIGN,                // btchip_apdu_hash_sign,
    BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, // btchip_apdu_hash_input_finalize_full,
    BTCHIP_INS_SIGN_MESSAGE,             // btchip_apdu_sign_message,
    BTCHIP_INS_GET_COIN_VER,             // btchip_apdu_get_coin_version
};

unsigned char const DISPATCHER_DATA_IN[] = {
    1, // btchip_apdu_get_wallet_public_key,
    1, // btchip_apdu_get_trusted_input,
    1, // btchip_apdu_hash_input_start,
    1, // btchip_apdu_hash_sign,
    1, // btchip_apdu_hash_input_finalize_full,
    1, // btchip_apdu_sign_message,
    0, // btchip_apdu_get_coin_version
};

apduProcessingFunction const DISPATCHER_FUNCTIONS[] = {
    btchip_apdu_get_wallet_public_key,
    btchip_apdu_get_trusted_input,
    btchip_apdu_hash_input_start,
    btchip_apdu_hash_sign,
    btchip_apdu_hash_input_finalize_full,
    btchip_apdu_sign_message,
    btchip_apdu_get_coin_version,
};
