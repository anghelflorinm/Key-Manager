#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "macros.h"
#include "keys_all.h"
#include "message_crypt.h"

using namespace std;

void get_key_using_k3(const unsigned char* input, unsigned char* output){
    for(int i = 0; i < BLOCK_SIZE; i++){
        output[i] = (char)((unsigned char)input[i] ^ (unsigned char)K3[i]);
    }
}

int main(int argc, char** argv) {
    if(argc != 3){
        perror("[A] Invalid run format! To run : ./a CBC <input_file> | ./a CFB <input_file>\n");
        return 0;
    }
    if(strcmp(argv[1], "CBC") > 0 && strcmp(argv[1], "CFB") >0){
        perror("[A] Invalid run format! To run : ./a CBC <input_file> | ./a CFB <input_file>\n");
        return 0;
    }


    int fd_key_manager;
    sockaddr_in server_address{};
    socklen_t  address_size;
    int read_size_container = 0;
    unsigned char buffer[BUFFER_MAX_SIZE] = {0};
    char* required_mode_str = argv[1];
    char* path_to_file = argv[2];

    //Read the file input
    FILE* input_file = fopen(path_to_file, "rb");
    if(input_file == nullptr){
        perror("[A] Error opening the input file!\n");
        return 1;
    }
    unsigned char file_buffer[BUFFER_MAX_SIZE];
    fread(file_buffer, BUFFER_MAX_SIZE, sizeof(unsigned char), input_file);
    fseek(input_file, 0, SEEK_END);
    unsigned int file_size = ftell(input_file);

    REQUIRED_MODE required_mode = CBC;

    if(strcmp(required_mode_str, "CFB") == 0){
        required_mode = CFB;
    }
    printf("[A] Begin!\n");

    printf("[A] Chosen required mode is %s\n", required_mode_str);

    //Create the socket
    printf("[A] Creating socket for key manager...\n");
    if((fd_key_manager = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("[A] Failed to create the socket!\n");
        exit(EXIT_FAILURE);
    }
    printf("[A] Socket created!\n");

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);

    //Convert address to binary format
    if(inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <=0){
        perror("[A] Failed converting address!\n");
        exit(EXIT_FAILURE);
    }

    //Connect to the key manager
    printf("[A] Connecting to the key manager...\n");
    if(connect(fd_key_manager, (sockaddr*)&server_address, sizeof(server_address)) < 0){
        perror("[A] Failed to connect to Key Manager!\n");
        exit(EXIT_FAILURE);
    }
    printf("[A] Connected to the key manager!\n");

    //Send the required mode to the key manager
    printf("[A] Sending the required mode to the key manager...\n");
    send(fd_key_manager, required_mode_str, strlen(required_mode_str), 0);

    //Receive the encryption key, XORed by K3
    unsigned char key[KEY_LEN] = {0};
    read(fd_key_manager, buffer, KEY_LEN);
    printf("[A] Received the encryption key from the key manager!\n");
    get_key_using_k3(buffer, key);

    //Receive the initialization vector
    unsigned char iv[KEY_LEN] = {0};
    read(fd_key_manager, buffer, KEY_LEN);
    printf("[A] Received the initialization vector from the key manager!\n");
    get_key_using_k3(buffer, iv);

    //encrypt and send confirmation message
    printf("[A] Encrypting the confirmation message...\n");
    unsigned char confirm_message[BUFFER_MAX_SIZE] = "CONFIRMCONFIRMCO";
    unsigned char encrypted_buffer[BUFFER_MAX_SIZE];
    unsigned int output_size_container = 0;
    encrypt_message(confirm_message, BLOCK_SIZE, encrypted_buffer, output_size_container, key, iv, required_mode);
    printf("[A] Sending the encrypted confirmation message to the key manager...\n");
    send(fd_key_manager, encrypted_buffer, output_size_container, 0);

    //receive the INIT_OK message
    printf("[A] Waiting for confirmation from the key manager!\n");
    read(fd_key_manager, buffer, BUFFER_MAX_SIZE);
    if(strcmp((const char*)buffer, "INIT_OK") != 0){
        perror("[A] INIT_OK not valid!\n");
    }
    printf("[A] Received confirmation from the key manager!\n");

    //Wait for the key manager to send you confirmation that server B is open
    usleep(100);
    printf("[A] Waiting for notification from the key manager that B has started listening for messages!\n");
    read(fd_key_manager, buffer, BUFFER_MAX_SIZE);
    printf("[A] Client B has started listening! Connecting to B...\n");
    if(strcmp((const char*)buffer, "BEGIN") != 0){
        perror("[A] Invalid begin message!\n");
    }

    //Start connecting to client B
    int fd_b;
    sockaddr_in b_address{};
    socklen_t  b_address_size;

    //Create the socket
    printf("[A] Creating socket for B...\n");
    if((fd_b = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("[A] Failed to create the socket!\n");
        exit(EXIT_FAILURE);
    }
    printf("[A] Socket for B created\n");

    b_address.sin_family = AF_INET;
    b_address.sin_port = htons(PORT_B);

    //Convert address to binary format
    if(inet_pton(AF_INET, "127.0.0.1", &b_address.sin_addr) <=0){
        perror("[A] Failed converting address!\n");
        exit(EXIT_FAILURE);
    }

    //Connect to the client
    if(connect(fd_b, (sockaddr*)&b_address, sizeof(b_address)) < 0){
        perror("[A] Failed to connect to client B!\n");
        exit(EXIT_FAILURE);
    }
    printf("[A] Connected to client B!\n");

    //encrypt the file content and send it to B
    printf("[A] Encrypting the file content and sending it to B...\n");
    unsigned char encrypted_file[BUFFER_MAX_SIZE];
    encrypt_message(file_buffer, file_size, encrypted_file, output_size_container, key, iv, required_mode);
    send(fd_b, encrypted_file, output_size_container, 0);

    //send the number of encrypted blocks to the key manager
    printf("[A] Sending the number of encrypted blocks to the key manager...\n");
    unsigned int nr_of_blocks = output_size_container / BLOCK_SIZE;
    send(fd_key_manager, &nr_of_blocks, sizeof(unsigned int), 0);

    printf("[A] Done!\n");
    return 0;
}


