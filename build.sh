g++ -o a a.cpp message_crypt.cpp -ldl -lcrypto
g++ -o b b.cpp message_crypt.cpp -ldl -lcrypto
g++ -o key_manager key_manager.cpp message_crypt.cpp -ldl -lcrypto -lpthread

