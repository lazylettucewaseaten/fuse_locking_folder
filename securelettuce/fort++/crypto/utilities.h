#pragma once

#include<string>
#include<vector>

std::string base64Encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> generatesalt();
std::vector<uint8_t> generateMasterKey();
std::vector<uint8_t> ivkey();
