#pragma once

#define BITID_NONE 0
#define BITID_POWERCYCLE 1
#define BITID_MULTIPLE 2

unsigned char message_check_bit_id(unsigned char *bip32Path);
unsigned short message_compute_hash(void);
