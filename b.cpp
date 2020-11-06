#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include "macros.h"
#include "keys_all.h"
#include "message_crypt.h"


using namespace std;

void get_key_using_k3(const unsigned char* input, unsigned char* output){
    for(int i = 0; i < BLOCK_SIZE; i++){
        output[i] = (char)((unsigned char)input[i] ^ (unsigned char)K3[i]);
    }
}


int main() {
    sockaddr_in server_address{};
    int fd_client;
    REQUIRED_MODE required_mode = CBC;
    unsigned char buffer[BUFFER_MAX_SIZE] = {0};

    printf("[B] Begin!\n");

    //Create the socket
    printf("[B] Creating socket for key manager...\n");
    if((fd_client = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("[B] Failed to create the socket!\n");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);

    //Convert address to binary format
    if(inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <=0){
        perror("[B] Failed converting address!\n");
        exit(EXIT_FAILURE);
    }

    //Connect to the client
    printf("[B] Connecting to the key manager...\n");
    if(connect(fd_client, (sockaddr*)&server_address, sizeof(server_address)) < 0){
        perror("[B] Failed to connect to Key Manager!");
        exit(EXIT_FAILURE);
    }
    printf("[B] Connected to the key manager!\n");

    //Wait to receive the encryption mode
    printf("[B] Waiting to receive the encryption mode from the key manager...\n");
    read(fd_client, buffer, BUFFER_MAX_SIZE);
    printf("[B] Received the encryption mode!\n");
    printf("[B] Will be using encryption mode: %s\n", buffer);
    if(strncmp((const char*)buffer, "CFB", 3) == 0){
        required_mode = CFB;
    }

    //Receive the encripition key, XORed by K3
    printf("aici\n");
    unsigned char key[KEY_LEN] = {0};
    //usleep(1);
    read(fd_client, buffer, BLOCK_SIZE);
    printf("[B] Received the encryption key from the key manager!\n");
    get_key_using_k3(buffer, key);

    //Receive the initialization vector
    unsigned char iv[KEY_LEN] = {0};
    read(fd_client, buffer, BLOCK_SIZE);
    printf("[B] Received the initialization vector from the key manager!\n");
    get_key_using_k3(buffer, iv);

    //encrypt and send the confirm message
    printf("[B] Encrypting the confirmation message...\n");
    unsigned char confirm_message[BUFFER_MAX_SIZE] = "CONFIRMCONFIRMCO";
    unsigned char encrypted_buffer[BUFFER_MAX_SIZE];
    unsigned int output_size_container = 0;
    encrypt_message(confirm_message, BLOCK_SIZE, encrypted_buffer, output_size_container, key, iv, required_mode);
    printf("[B] Sending the encrypted confirmation message to the key manager...\n");
    send(fd_client, encrypted_buffer, output_size_container, 0);

    //receive the INIT_OK message
    printf("[B] Waiting for confirmation from the key manager!\n");
    read(fd_client, buffer, BUFFER_MAX_SIZE);
    if(strcmp((const char*)buffer, "INIT_OK") != 0){
        perror("[B] INIT_OK not valid!\n");
        exit(-1);
    }
    printf("[B] Received confirmation from the key manager!\n");

    //Start listening on B client
    printf("[B] Start opening socket and listening to A to sen encrypted message!\n");
    sockaddr_in b_address{};
    int option = 1;
    int server_fd;
    int fd_a;
    int b_address_size = sizeof(b_address);

    //Create the socket
    printf("[B] Creating socket for listening!...\n");
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("[KM] Fail to create the socket!");
        return 1;
    }
    printf("[B] Socket for listening created!\n");

    //Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, (unsigned int) SO_REUSEADDR | (unsigned int) SO_REUSEPORT, &option,
                   sizeof(option))) {
        perror("[KM] Failed setting the socket options!");
        return 1;
    }

    b_address.sin_family = AF_INET;
    b_address.sin_addr.s_addr = INADDR_ANY;
    b_address.sin_port = htons(PORT_B);

    //Bind socket to port and address
    printf("[B] Binding socket to address...\n");
    if (bind(server_fd, (sockaddr *) &b_address, sizeof(b_address)) < 0) {
        perror("[B] Bind failed!");
        return 1;
    }
    printf("[B] Socket binded to address!\n");

    //Start listening
    printf("[B] Start listening!\n");
    if (listen(server_fd, MAX_CONNECTIONS) < 0) {
        perror("[B] Listen failed!");
        return 1;
    }
    printf("[B] Listening on port %d...\n", PORT_B);
    fflush(stdout);

    //Tell the key manager that the server is running and A can launch connection
    printf("[B] Telling the key manager to tell A that it can start sending encrypted content!\n");
    send(fd_client, "BEGIN", sizeof("BEGIN"), 0);

    //accept client A
    printf("[B] Waiting for client A to connect...\n");
    if ((fd_a = accept(server_fd, (sockaddr *) &b_address, (socklen_t *) (&b_address_size))) < 0) {
        perror("[B] Failed accepting client A!\n");
        return 1;
    }
    printf("[B] Client A connected!!\n");

    //Receive the encrypted message from A and decrypt it
    unsigned char decrypted_buffer[BUFFER_MAX_SIZE];
    unsigned int buffer_size = read(fd_a, encrypted_buffer, BUFFER_MAX_SIZE);
    printf("[B] Received the encrypted file content!\n");
    decrypt_message(encrypted_buffer, buffer_size, decrypted_buffer, output_size_container, key, iv, required_mode);
    printf("[B] Decrypted the file content!\n");
    printf("[B] Got the following file content:\n");
    fwrite((decrypted_buffer), output_size_container, sizeof(char), stdout);

    //send the number of blocks to the Key Manager
    printf("\n[B] Sending the number of blocks to the key manager...\n");
    unsigned int number_of_blocks = buffer_size / BLOCK_SIZE;
    send(fd_client, &number_of_blocks, sizeof(unsigned int), 0);
    printf("[B] Done!\n");
    return 0;
}
