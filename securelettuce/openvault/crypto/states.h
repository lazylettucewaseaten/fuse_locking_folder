#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

struct FileMeta {
    std::string plain;
    std::string cipher;
    uint64_t size;
};

struct State {
    std::string enc_dir;
    std::vector<uint8_t> MK; 
    int iv_len = 12;
    int tag_len = 16;
    std::unordered_map<std::string, FileMeta> pt_map; //text to meta
    std::unordered_map<std::string, std::string> ct_to_pt; // c to p
};


//global declaration will be used later
extern State GSTATE;
extern std::mutex g_state_mutex;


// constants used by fuse
// constexpr uint64_t FILE_HEADER_MAGIC = 0xDEADBEEFCAFEF00D;
// constexpr size_t FILE_HEADER_SIZE = 16;
constexpr size_t PLAINTEXT_BLOCK_SIZE = 4096;
constexpr size_t IV_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
constexpr size_t CIPHERTEXT_BLOCK_SIZE = IV_SIZE + PLAINTEXT_BLOCK_SIZE + TAG_SIZE;


struct FileHeader {
    uint64_t magic;         // A constant magic number to identify the file type
    uint64_t plaintext_size; // The exact size of the original plaintext file
};
constexpr uint64_t FILE_HEADER_MAGIC = 0xDEADBEEFCAFEF00D;
constexpr size_t FILE_HEADER_SIZE = sizeof(FileHeader); // Correctly use sizeof