#pragma once
#include <cstdint>
#include <vector>
#include <string>

//encryption ,decryption for the file or anything related or password
bool aes256_gcm_encrypt_blob(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad,
    std::vector<uint8_t>& ciphertext_out,
    std::vector<uint8_t>& tag_out
);

bool aes256_gcm_decrypt_blob(
    const std::vector<uint8_t>& blob,
    const std::vector<uint8_t>& key,
    int iv_len, int tag_len,
    const std::vector<uint8_t>& aad,
    std::vector<uint8_t>& plaintxt_out
);


std::vector<uint8_t> derive_file_key(const std::string& path);
bool decrypting_master_key(const std::string &conf_path, const std::string &password, std::vector<uint8_t> &masterKeyOut);
std::vector<uint8_t>derivekeyscrypt(std::string &password,std::vector<uint8_t>&salt,std::uint64_t N ,std::uint64_t r,std::uint64_t p,std::vector<uint8_t>&data,int keyLen = 32);



std::vector<uint8_t> base64Decode(const std::string &in);
std::string base64Encode(const std::vector<uint8_t> &data);
std::string base64UrlToStd(const std::string &s);
std::string base64StdToUrl(std::string s);
