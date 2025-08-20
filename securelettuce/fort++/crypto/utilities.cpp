

#include <openssl/bio.h>
#include<openssl/buffer.h>
#include <openssl/evp.h> 
#include "utilities.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdexcept>

std::string base64Encode(const std::vector<uint8_t>& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // no newlines
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}


std::vector<uint8_t>generatesalt(){
    std::vector<uint8_t>salt(16);
    if(RAND_bytes(salt.data(),salt.size())!=1){
        throw std::runtime_error("Random allocation failed\n");
    }
    return salt;
}

std::vector<uint8_t>generateMasterKey(){
    int len=32;
    std::vector<uint8_t>key(len);
    if(RAND_bytes(key.data(),len)!=1){
        throw std::runtime_error("Random allocation failed\n");
    }
    return key;
}



std::vector<uint8_t>ivkey(){
    int len=12;
    std::vector<uint8_t>key(len);
    if(RAND_bytes(key.data(),len)!=1){
        throw std::runtime_error("Random allocation failed\n");
    }
    return key;
}
