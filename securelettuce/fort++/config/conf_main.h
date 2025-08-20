#pragma once

#include<string>
#include<vector>
#include<cstdint>
#include<iostream>
#include<sys/stat.h>
#include<fstream>

void saveconf(std::string &path,std::vector<uint8_t>&encryptedkey,std::vector<uint8_t>&salt,std::vector<uint8_t>&ivout,std::vector<uint8_t>&tagout);
void savediriv(const std::string &path, const std::vector<uint8_t> &iv);
