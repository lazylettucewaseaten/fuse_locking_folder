
#include "conf_main.h"
#include<iostream>

#include<vector>
#include<string>
#include <nlohmann/json.hpp>
#include "../crypto/utilities.h"  //errro here
#include <sys/stat.h>
#include <fstream>
#include<stdexcept>
#include<unistd.h>
using namespace nlohmann;


void saveconf(std::string &path,std::vector<uint8_t>&encryptedkey,std::vector<uint8_t>&salt,std::vector<uint8_t>&ivout,std::vector<uint8_t>&tagout){
    json j;
    j["Creator"] = "lazylocking 1.0";
    j["EncryptedKey"] = base64Encode(encryptedkey);
    j["Salt"] = base64Encode(salt);
    j["KDF"] = {
        {"Function", "EVP_PBE_scrypt"},
        {"KeyLen", 32}
    };
    j["ScryptObject"] = {
        {"N", 1<<16},
        {"R", 8},
        {"P", 2},
        {"KeyLen", 32}
    };
    j["Cipher"] = "AES-256-GCM";
    j["IV"]=base64Encode(ivout),
    j["TAG"]=base64Encode(tagout);     
    j["IVLen"] = 12;
    j["TagLen"] = 16;
    j["Version"] = 1;
    j["FeatureFlags"] = {"DirIV", "AES-GCM"};

    std::ofstream ofs(path+"/lazylocking.conf",std::ios::trunc);
    //understand ios trunc
    ofs<<j.dump(4); 
    chmod((path + "/lazylocking.conf").c_str(), S_IRUSR | S_IWUSR); // 600
}


void savediriv(const std::string &path, const std::vector<uint8_t> &iv) {
    std::ofstream ofs((path + "/.diriv").c_str(), std::ios::binary | std::ios::trunc);
    if (!ofs) {
        throw std::runtime_error(std::string("failed to open .diriv for writing: ") + path + "/.diriv");
    }
    if (!iv.empty()) ofs.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    ofs.close();
    // optionally set mode 600:
    chmod((path + "/.diriv").c_str(), S_IRUSR | S_IWUSR);
}
