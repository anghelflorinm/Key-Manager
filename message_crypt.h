#ifndef TEMA1_MESSAGE_CRYPT_H
#define TEMA1_MESSAGE_CRYPT_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include "macros.h"

void
encrypt_message(unsigned char *plaintext, unsigned int plaintext_size, unsigned char *output, unsigned int &output_size,
                const unsigned char *enc_key, const unsigned char *iv, REQUIRED_MODE required_mode);

void decrypt_message(unsigned char *ciphertext, unsigned int ciphertext_size, unsigned char *output,
                     unsigned int &output_size, const unsigned char *enc_key, const unsigned char *iv, REQUIRED_MODE required_mode);

#endif //TEMA1_MESSAGE_CRYPT_H
