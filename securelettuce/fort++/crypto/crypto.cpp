#include "crypto.h"

#include<openssl/evp.h>
#include<openssl/err.h>
#include<stdexcept>
std::vector<uint8_t>derivekeyscrypt(std::string &password,std::vector<uint8_t>&salt,uint64_t N ,uint64_t r,uint64_t p,int keyLen){
    std::vector<uint8_t>data(keyLen);

    if (EVP_PBE_scrypt(password.c_str(),password.size(),
                       salt.data(),salt.size(),
                       N,r,p,0x7fffffff,   // high memory limit
                       data.data(),keyLen)!=1){
                          throw std::runtime_error(std::string("EVP_PBE_scrypt failed: ") );
                        }

    return data;
}
std::vector<uint8_t>derivekey(std::string &password,std::vector<uint8_t>&salt,int len){
    //our out is the key  
    // we use .c_str for convetiosn of string into char* 
    // read documentaion for the PKCS5 for chaning it
    // PKCS5_PBKDF2_HMAC(password.c_str(),(int)password.size(),salt.data(),(int)salt.size(),iterations,EVP_sha512(),len,out.data());
    uint64_t N=1<<16;
    uint64_t r=8;
    uint64_t p=2;

    return derivekeyscrypt(password,salt,N,r,p,len);
}


std::vector<uint8_t> encryptkey(const std::vector<uint8_t>& plaintext,
                           const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& ivOut,
                           std::vector<uint8_t>& tagOut)
{
    std::vector<uint8_t> ciphertext;
    ciphertext.resize(plaintext.size() + 16); // room for possible padding though GCM doesn't pad
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int outlen = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), ivOut.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex(key/iv) failed");
    }

    //tho it may never run as qwe need password 
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen,
                              plaintext.data(), (int)plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }
    } else {
        outlen = 0;
    }
    //we hae written something after ttthe update so we statr filling cipher after that therfore we add the eoutlen, adn templene store s howmany bytes we have store int he final step
    int total = outlen;
    int tmplen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data()+outlen,&tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    total += tmplen;

    tagOut.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tagOut.size(), tagOut.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl(GET_TAG) failed");
    }

    ciphertext.resize(total);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}