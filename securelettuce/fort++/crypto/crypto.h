#pragma once


#include<vector>
#include<cstdint>
#include<string>
std::vector<uint8_t>derivekeyscrypt(std:: string &password,std::vector<uint8_t>&salt,uint64_t N ,uint64_t r,uint64_t p,int keyLen = 32);
std::vector<uint8_t>derivekey(std::string &password,std::vector<uint8_t>&salt,int len=32);
std::vector<uint8_t> encryptkey(const std::vector<uint8_t>& plaintext,
                           const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& ivOut,
                           std::vector<uint8_t>& tagOut);