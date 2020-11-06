#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "macros.h"
#include "keys_all.h"
#include "keys_manager.h"
#include "message_crypt.h"

using namespace std;
mutex mtx;
condition_variable cond_var;


struct server_context{
    int fd_a  = -1;
    int fd_b = -1;
    REQUIRED_MODE required_mode = CBC;
    unsigned int nr_of_blocks_a = 0;
    unsigned int nr_of_blocks_b = 0;
};

void encrypt_key_with_k3(unsigned char* output, REQUIRED_MODE required_mode, bool initialization_vector){
    //We will send through the network either K1 XOR K3, either K2 XOR K3 depending on the selected mode
    const unsigned char* K = (initialization_vector ? iv : required_mode == CBC ? K1 : K2);

    //Perform XOR between the two keys
    for(int i = 0; i < 16; i++){
        output[i] = (char)((unsigned char)K[i] ^ (unsigned char)K3[i]);
    }
}

void handle_a(server_context& srv_context){
    unsigned int size_container;
    unsigned char buffer[BUFFER_MAX_SIZE];
    printf("[KM] Client A connected!\n");

    //Receive the desired encryption mode
    printf("[KM] Waiting to receive the encryption mode from A...\n");
    read(srv_context.fd_a, buffer, BUFFER_MAX_SIZE);
    if(strcmp((const char*)buffer, "CFB") == 0){
        srv_context.required_mode = CFB;
    }
    printf("[KM] Received encryption mode %s from A!\n", buffer);
    cond_var.notify_one();

    //Encrypt and send the corresponding key
    printf("[KM] Encrypting the chosen key!\n");
    encrypt_key_with_k3(buffer, srv_context.required_mode, false);
    printf("[KM] Sending key to A...\n");
    send(srv_context.fd_a, buffer, KEY_LEN, 0);

    //Send the iv
    printf("[KM] Encrypting the iv!\n");
    encrypt_key_with_k3(buffer, srv_context.required_mode, true);
    printf("[KM] Sending IV to A...\n");
    send(srv_context.fd_a, buffer, KEY_LEN, 0);


    //Receive the encrypted confirm message, decrypt it, then check
    printf("[KM] Waiting for encrypted confirmation message from A...\n");
    read(srv_context.fd_a, buffer, BUFFER_MAX_SIZE);
    const unsigned char* K = (srv_context.required_mode == CBC ? K1 : K2);
    unsigned char decrypted_buffer[BUFFER_MAX_SIZE];
    unsigned int output_size_container = 0;
    printf("[KM] Message from A received! Decrypting and checking it...\n");
    decrypt_message(buffer, BLOCK_SIZE, decrypted_buffer, output_size_container, K, iv, srv_context.required_mode);
    if(strncmp((const char*) decrypted_buffer, "CONFIRMCONFIRMCO", sizeof("CONFIRMCONFIRMCO") - 1) != 0){
        perror("[KM] Did not receive proper confirmation message from client A");
        exit(1);
    }
    printf("[KM] Confirmation message from A is ok!\n");

    //send the init_ok message
    printf("[KM] Telling A that the confirmation message was received and is ok!\n");
    send(srv_context.fd_a, "INIT_OK", sizeof("INIT_OK"), 0);

    //wait for B to open the ports
    printf("[KM] Waiting for B to become available for sending messages...\n");
    unique_lock<mutex> lck(mtx);
    cond_var.wait(lck);

    //Tell A that it can begin connecting to B
    printf("[KM] B is listening! Telling A it can start communicating with B!\n");
    send(srv_context.fd_a, "BEGIN", sizeof("BEGIN"), 0);
    printf("[KM] Waiting for number of decrypted blocks from A...\n");
    read(srv_context.fd_a, &srv_context.nr_of_blocks_a, sizeof(unsigned int));
}

void handle_b(server_context& srv_context){
    unsigned char buffer[BUFFER_MAX_SIZE];
    printf("[KM] Client B connected!\n");
    unique_lock<mutex> lck(mtx);

    //Wait for client A to connect
    printf("[KM] Waiting for client A to connect...\n");
    if(srv_context.fd_a  == -1){
        cond_var.wait(lck);
    }
    lck.unlock();

    //Send the encryption mode to B
    if(srv_context.required_mode == CBC){
        strcpy((char*)buffer, "CBC");
    }
    else{
        strcpy((char*)buffer, "CFB");
    }
    printf("[KM] Sending chosen encryption mode to B...\n");
    send(srv_context.fd_b, buffer, strlen((const char*)buffer), 0);
    //Encrypt and send the corresponding key
    encrypt_key_with_k3(buffer, srv_context.required_mode, false);
    printf("[KM] Sending key to B...\n");
    send(srv_context.fd_b, buffer, KEY_LEN, 0);

    //Send the iv
    encrypt_key_with_k3(buffer, srv_context.required_mode, true);
    printf("[KM] Sending IV to B...\n");
    send(srv_context.fd_b, buffer, KEY_LEN, 0);

    //Receive the encrypted confirm message, decrypt it, then check
    printf("[KM] Waiting for encrypted confirmation message from B...\n");
    read(srv_context.fd_b, buffer, BUFFER_MAX_SIZE);
    const unsigned char* K = (srv_context.required_mode == CBC ? K1 : K2);
    unsigned char decrypted_buffer[BUFFER_MAX_SIZE];
    unsigned int output_size_container = 0;
    printf("[KM] Message from B received! Decrypting and checking it...\n");
    decrypt_message(buffer, BLOCK_SIZE, decrypted_buffer, output_size_container, K, iv, srv_context.required_mode);
    if(strncmp((const char*) decrypted_buffer, "CONFIRMCONFIRMCO", sizeof("CONFIRMCONFIRMCO") - 1) != 0){
        perror("[KM] Did not receive proper confirmation message from client B");
        exit(1);
    }
    printf("[KM] Confirmation message from B is ok!\n");

    //send the init_ok message
    printf("[KM] Telling B that the confirmation message was received and is ok!\n");
    send(srv_context.fd_b, "INIT_OK", sizeof("INIT_OK"), 0);

    printf("[KM] Waiting for notification from B that it has started listening...\n");
    read(srv_context.fd_b, buffer, BUFFER_MAX_SIZE);
    if(strcmp((const char*)buffer, "BEGIN") != 0){
        perror("[KM] Invalid BEGIN message from client B!\n");
        exit(-1);
    }
    cond_var.notify_one();
    printf("[KM] Waiting to receive number of encrypted blocks from B!\n");
    read(srv_context.fd_b, &srv_context.nr_of_blocks_b, sizeof(unsigned int));
}

int main() {
    sockaddr_in server_address{};
    int option = 1;
    int server_fd = 0;
    int fd_a = 0;
    int fd_b = 0;
    int address_size = sizeof(server_address);

    //Create the socket
    printf("[KM] Creating the socket...\n");
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("[KM] Fail to create the socket!");
        return 1;
    }
    printf("[KM] Socket created!\n");

    //Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, (unsigned int) SO_REUSEADDR | (unsigned int) SO_REUSEPORT, &option,
                   sizeof(option))) {
        perror("[KM] Failed setting the socket options!");
        return 1;
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    //Bind socket to port and address
    printf("[KM] Binding socket to address...\n");
    if (bind(server_fd, (sockaddr *) &server_address, sizeof(server_address)) < 0) {
        perror("[KM] Bind failed!");
        return 1;
    }
    printf("[KM] Socket binded to address!\n");

    //Start listening
    printf("[KM] Start listening!\n");
    if (listen(server_fd, MAX_CONNECTIONS) < 0) {
        perror("[KM] Listen failed!");
        return 1;
    }
    printf("[KM] Listening on port %d...\n", PORT);
    fflush(stdout);

    server_context srv_context{};

    //Accept client B
    printf("[KM] Waiting for client B to connect...\n");
    if ((fd_b = accept(server_fd, (sockaddr *) &server_address, (socklen_t *) (&address_size))) < 0) {
        perror("[KM] Failed accepting client B!\n");
        return 1;
    }

    //Start handling for client B
    srv_context.fd_b = fd_b;
    thread thread_b(handle_b, ref(srv_context));

    //Accept client A
    printf("[KM] Waiting for client B to connect...\n");
    if ((fd_a = accept(server_fd, (sockaddr *) &server_address, (socklen_t *) (&address_size))) < 0) {
        perror("[KM] Failed accepting client A!\n");
        return 1;
    }

    //Start handling for client A
    srv_context.fd_a = fd_a;
    thread thread_a(handle_a, ref(srv_context));

    thread_a.join();
    thread_b.join();
    printf("[KM] Received number of blocks from A: %u\n", srv_context.nr_of_blocks_a);
    printf("[KM] Received number of blocks from B: %u\n", srv_context.nr_of_blocks_b);

    if(srv_context.nr_of_blocks_a != srv_context.nr_of_blocks_b){
        perror("[KM] The number of blocks is not equal!!\n");
        return 1;
    }
    printf("[KM] The number of bytes is equal!\n");
    printf("[KM] Done!\n");
    return 0;
}
