#include "message_crypt.h"

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void xor_blocks(const unsigned char* input1, const unsigned char* input2, unsigned char* output){
    for(int i = 0; i < BLOCK_SIZE; i++){
        output[i] = (char)((unsigned char)input1[i] ^ (unsigned char)input2[i]);
    }
}

void encrypt_ecb(unsigned char *plaintext, unsigned char *output, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr))
        handleErrors();

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, output, &len, plaintext, BLOCK_SIZE))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, output + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    //return ciphertext_len;
}

void decrypt_ecb(unsigned char *ciphertext, unsigned char *output, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr))
        handleErrors();

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, output, &len, ciphertext, BLOCK_SIZE))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, output + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    //return plaintext_len;
}

void encrypt_CBC(const unsigned char *plaintext, unsigned int plaintext_size, unsigned char *ciphertext,
                 const unsigned char *enc_key, const unsigned char *iv) {
    const unsigned int nr_blocks = plaintext_size / BLOCK_SIZE;
    unsigned char input_block[BLOCK_SIZE] = {0};

    memcpy(input_block, iv, BLOCK_SIZE);
    for(int i = 0; i < nr_blocks; ++i){
        unsigned char xor_output[BLOCK_SIZE];
        xor_blocks(plaintext + i * BLOCK_SIZE, input_block, xor_output);

        unsigned char encrypted_block[BLOCK_SIZE] = {0};
        encrypt_ecb(xor_output, encrypted_block, enc_key);
        memcpy(ciphertext + i * BLOCK_SIZE, encrypted_block, BLOCK_SIZE);
        memcpy(input_block, encrypted_block, BLOCK_SIZE);
    }
}

void encrypt_CFB(const unsigned char *plaintext, const unsigned int plaintext_size, unsigned char *ciphertext,
                 const unsigned char *enc_key, const unsigned char *iv) {
    const unsigned int nr_blocks = plaintext_size / BLOCK_SIZE;
    unsigned char input_block[BLOCK_SIZE] = {0};

    memcpy(input_block, iv, BLOCK_SIZE);
    for(int i = 0; i < nr_blocks; i++){
        unsigned char encrypted_block[BLOCK_SIZE] = {0};
        encrypt_ecb(input_block, encrypted_block, enc_key);
        xor_blocks(encrypted_block, plaintext + i * BLOCK_SIZE, ciphertext + i * BLOCK_SIZE);
        memcpy(input_block, ciphertext + i * BLOCK_SIZE, BLOCK_SIZE);
    }
}

void decrypt_CBC(unsigned char *ciphertext, const unsigned int ciphertext_size, unsigned char *output,
                 const unsigned char *enc_key, const unsigned char *iv) {
    const unsigned int nr_blocks = ciphertext_size / BLOCK_SIZE;
    unsigned char input_block[BLOCK_SIZE] = {0};

    memcpy(input_block, iv, BLOCK_SIZE);
    for(int i = 0; i < nr_blocks; i++){
        unsigned char decrypted_block[BLOCK_SIZE] = {0};
        decrypt_ecb(ciphertext + i * BLOCK_SIZE, decrypted_block, enc_key);
        xor_blocks(decrypted_block, input_block, output + i * BLOCK_SIZE);
        memcpy(input_block, ciphertext + i * BLOCK_SIZE, BLOCK_SIZE);
    }
}

void decrypt_CFB(unsigned char *ciphertext, const unsigned int ciphertext_size, unsigned char *plaintext,
                 const unsigned char *enc_key, const unsigned char *iv) {
    const unsigned int nr_blocks = ciphertext_size / BLOCK_SIZE;
    unsigned char input_block[BLOCK_SIZE] = {0};

    memcpy(input_block, iv, BLOCK_SIZE);
    for(int i = 0; i < nr_blocks; i++){
        unsigned char encrypted_block[BLOCK_SIZE * 2] = {0};
        encrypt_ecb(input_block, encrypted_block, enc_key);
        xor_blocks(encrypted_block, ciphertext + i * BLOCK_SIZE, plaintext + i * BLOCK_SIZE);
        memcpy(input_block, ciphertext + i * BLOCK_SIZE, BLOCK_SIZE);
    }
}

unsigned int pad_buffer(unsigned char *buffer, const unsigned int input_size) {
    //Chosen Padding: PKCS
    unsigned int remainder = BLOCK_SIZE - (input_size % BLOCK_SIZE);
    if (remainder % BLOCK_SIZE == 0 && input_size > 0) {
        if (buffer[input_size - 1] != 1) {
            return input_size;
        }
        //Pad with another block containing 0x1 if BLOCK_SIZE is multiple of 16 and ends in 1
        memset(buffer + input_size, 1, BLOCK_SIZE);
        return input_size + BLOCK_SIZE;
    }
    //Pad with the remainder bytes
    memset(buffer + input_size, (int) remainder, remainder);
    return input_size + remainder;
}

unsigned int get_size_without_pad(const unsigned char* buffer, const unsigned int input_size){
    if(input_size == 0){
        return 0;
    }
    int bytes_to_check = 0;
    if(buffer[input_size - 1] == 1){
        bytes_to_check = 16;
    }
    else{
        if(bytes_to_check >= BLOCK_SIZE){
            return input_size;
        }
        if(buffer[input_size - 1] >= 16){
            return input_size;
        }
        bytes_to_check = buffer[input_size - 1];
    }
    for(int i = 0; i < bytes_to_check; i++){
        if(buffer[input_size - bytes_to_check - 1] != buffer[input_size - 1]){
            return input_size;
        }
    }
    return input_size - bytes_to_check;
}

void
encrypt_message(unsigned char *plaintext, const unsigned int plaintext_size, unsigned char *output,
                unsigned int &output_size,
                const unsigned char *enc_key, const unsigned char *iv, REQUIRED_MODE required_mode) {
    output_size = pad_buffer(plaintext, plaintext_size);
    switch (required_mode) {
        case CFB:
            encrypt_CFB(plaintext, output_size, output, enc_key, iv);
            break;
        case CBC:
        default:
            encrypt_CBC(plaintext, output_size, output, enc_key, iv);
            break;
    }

}

void decrypt_message(unsigned char *ciphertext, const unsigned int ciphertext_size, unsigned char *output,
                     unsigned int &output_size, const unsigned char *enc_key, const unsigned char *iv,
                     REQUIRED_MODE required_mode) {
    switch (required_mode) {
        case CFB:
            decrypt_CFB(ciphertext, ciphertext_size, output, enc_key, iv);
            break;
        case CBC:
        default:
            decrypt_CBC(ciphertext, ciphertext_size, output, enc_key, iv);
            break;
    }
    output_size = get_size_without_pad(output, ciphertext_size);
}


