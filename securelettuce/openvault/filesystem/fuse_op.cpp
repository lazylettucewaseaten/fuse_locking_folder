// fuse_op.cpp
#include "fuse_op.h"
#include "../crypto/states.h"
#include "../crypto/crypto.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string.h> // For memset
#include <errno.h>
#include <openssl/rand.h>

using namespace std;
namespace fs = filesystem;

// ------------------------------------------------------------------
// Helper to read the file header and get the exact plaintext size
// ------------------------------------------------------------------
static bool read_file_header(const fs::path& cpath, FileHeader& header) {
    // Check if the file is large enough to contain the header
    if (fs::file_size(cpath) < FILE_HEADER_SIZE) {
        return false;
    }
    ifstream ifs(cpath, ios::binary);
    if (!ifs) return false;

    ifs.read(reinterpret_cast<char*>(&header), FILE_HEADER_SIZE);

    return header.magic == FILE_HEADER_MAGIC;
}

static bool write_file_header(const fs::path& cpath, const FileHeader& header) {
    // Use fstream to open for read/write without truncating
    fstream ofs(cpath, ios::in | ios::out | ios::binary);
    if (!ofs) { // If the file doesn't exist, create it
        ofstream create_ofs(cpath, ios::binary | ios::trunc);
        if(!create_ofs) return false;
        create_ofs.write(reinterpret_cast<const char*>(&header), FILE_HEADER_SIZE);
    } else { // If it exists, seek to the beginning and overwrite the header
        ofs.seekp(0, ios::beg);
        ofs.write(reinterpret_cast<const char*>(&header), FILE_HEADER_SIZE);
    }
    return true;
}


void build_name_map() {
    GSTATE.pt_map.clear();
    GSTATE.ct_to_pt.clear();

    for (auto &entry : filesystem::directory_iterator(GSTATE.enc_dir)) {
        if (!entry.is_regular_file()) continue;
        string fname = entry.path().filename().string();
        if (fname == "lazylocking.conf" || fname == ".diriv") continue;

        string std_b64 = base64UrlToStd(fname);
        auto raw = base64Decode(std_b64);
        if (raw.empty() || (int)raw.size() < GSTATE.iv_len + GSTATE.tag_len) continue;

        vector<uint8_t> plain;
        if (!aes256_gcm_decrypt_blob(raw, GSTATE.MK, GSTATE.iv_len, GSTATE.tag_len, {}, plain)) {
            continue;
        }
        string pname((char*)plain.data(), plain.size());
        
        FileMeta m;
        m.plain = pname;
        m.cipher = fname;
        
        FileHeader header;
        if (read_file_header(entry.path(), header)) {
            m.size = header.plaintext_size;
        } else {
            m.size = 0; 
        }

        GSTATE.pt_map[pname] = m;
        GSTATE.ct_to_pt[fname] = pname;
    }
}

int lz_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    std::lock_guard<std::mutex> lock(g_state_mutex);
    memset(stbuf, 0, sizeof(struct stat));
    string p(path);
    if (p == "/") {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }
    if (p.size() && p[0] == '/') p = p.substr(1);

    auto it = GSTATE.pt_map.find(p);
    if (it == GSTATE.pt_map.end()) return -ENOENT;

    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size = it->second.size; 
    
    return 0;
}

int lz_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                      struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void)offset; (void)fi; (void)flags;
    if (string(path) != "/") return -ENOENT;
    filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
    filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
    
    std::lock_guard<std::mutex> lock(g_state_mutex);
    for (const auto& pair : GSTATE.pt_map) {
        filler(buf, pair.first.c_str(), NULL, 0, FUSE_FILL_DIR_PLUS);
    }
    return 0;
}

int lz_open(const char *path, struct fuse_file_info *fi) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    string p(path);
    if (p.size() && p[0] == '/') p = p.substr(1);
    if (GSTATE.pt_map.find(p) == GSTATE.pt_map.end()) return -ENOENT;
    return 0;
}

int lz_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)mode; (void)fi;
    string p(path);
    if (p.size() && p[0] == '/') p = p.substr(1);

    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (GSTATE.pt_map.count(p)) return -EEXIST;

    vector<uint8_t> name_plain(p.begin(), p.end());
    vector<uint8_t> iv(GSTATE.iv_len);
    if (RAND_bytes(iv.data(), (int)iv.size()) != 1) return -EIO;
    vector<uint8_t> ct, tag;
    if (!aes256_gcm_encrypt_blob(name_plain, GSTATE.MK, iv, {}, ct, tag)) return -EIO;
    vector<uint8_t> name_blob;
    name_blob.insert(name_blob.end(), iv.begin(), iv.end());
    name_blob.insert(name_blob.end(), ct.begin(), ct.end());
    name_blob.insert(name_blob.end(), tag.begin(), tag.end());
    string url_b64 = base64StdToUrl(base64Encode(name_blob));

    fs::path cpath = fs::path(GSTATE.enc_dir) / url_b64;
    FileHeader header = {FILE_HEADER_MAGIC, 0};
    if (!write_file_header(cpath, header)) return -EIO;

    FileMeta meta;
    meta.plain = p;
    meta.cipher = url_b64;
    meta.size = 0;
    GSTATE.pt_map[p] = meta;
    GSTATE.ct_to_pt[url_b64] = p;
    return 0;
}

int lz_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)fi;
    string p(path);
    if (p.size() && p[0] == '/') p = p.substr(1);
    
    fs::path cpath;
    uint64_t file_size;
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto it = GSTATE.pt_map.find(p);
        if (it == GSTATE.pt_map.end()) return -ENOENT;
        cpath = fs::path(GSTATE.enc_dir) / it->second.cipher;
        file_size = it->second.size;
    }
    
    if (offset >= (off_t)file_size) return 0;
    if (offset + size > file_size) {
        size = file_size - offset;
    }

    auto file_key = derive_file_key(p);
    if (file_key.empty()) return -EIO;

    ifstream ifs(cpath, ios::binary);
    if (!ifs) return -EIO;

    size_t total_read = 0;
    size_t current_offset = offset;
    size_t remaining_size = size;

    while (remaining_size > 0) {
        size_t block_idx = current_offset / PLAINTEXT_BLOCK_SIZE;
        size_t offset_in_block = current_offset % PLAINTEXT_BLOCK_SIZE;
        
        off_t cipher_block_offset = FILE_HEADER_SIZE + block_idx * CIPHERTEXT_BLOCK_SIZE;
        ifs.seekg(cipher_block_offset, ios::beg);
        if (ifs.eof() || ifs.fail()) break;

        vector<uint8_t> encrypted_block(CIPHERTEXT_BLOCK_SIZE);
        ifs.read(reinterpret_cast<char*>(encrypted_block.data()), CIPHERTEXT_BLOCK_SIZE);
        if (ifs.gcount() < (long)(IV_SIZE + TAG_SIZE)) break;

        vector<uint8_t> plain_block;
        if (!aes256_gcm_decrypt_blob(encrypted_block, file_key, IV_SIZE, TAG_SIZE, {}, plain_block)) {
             break;
        }

        size_t to_copy = min(remaining_size, PLAINTEXT_BLOCK_SIZE - offset_in_block);
        if (offset_in_block + to_copy > plain_block.size()) {
             to_copy = plain_block.size() > offset_in_block ? plain_block.size() - offset_in_block : 0;
        }
        if (to_copy == 0) break;

        memcpy(buf + total_read, plain_block.data() + offset_in_block, to_copy);
        total_read += to_copy;
        current_offset += to_copy;
        remaining_size -= to_copy;
    }
    
    return total_read;
}

int lz_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)fi;
    string p(path);
    if (!p.empty() && p[0] == '/') p = p.substr(1);

    fs::path cpath;
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto it = GSTATE.pt_map.find(p);
        if (it == GSTATE.pt_map.end()) return -ENOENT;
        cpath = fs::path(GSTATE.enc_dir) / it->second.cipher;
    }

    auto file_key = derive_file_key(p);
    if (file_key.empty()) return -EIO;

    fstream iofs(cpath, ios::in | ios::out | ios::binary);
    if (!iofs) return -EIO;

    size_t total_written = 0;
    size_t current_offset = offset;
    size_t remaining_size = size;

    while (remaining_size > 0) {
        size_t block_idx = current_offset / PLAINTEXT_BLOCK_SIZE;
        size_t offset_in_block = current_offset % PLAINTEXT_BLOCK_SIZE;

        off_t cipher_block_offset = FILE_HEADER_SIZE + block_idx * CIPHERTEXT_BLOCK_SIZE;
        
        vector<uint8_t> plain_block(PLAINTEXT_BLOCK_SIZE, 0);

        if (offset_in_block > 0 || remaining_size < PLAINTEXT_BLOCK_SIZE) {
            iofs.seekg(cipher_block_offset, ios::beg);
            vector<uint8_t> encrypted_block(CIPHERTEXT_BLOCK_SIZE);
            iofs.read(reinterpret_cast<char*>(encrypted_block.data()), CIPHERTEXT_BLOCK_SIZE);
            if (iofs.gcount() >= (long)(IV_SIZE + TAG_SIZE)) {
                vector<uint8_t> decrypted_block;
                if (aes256_gcm_decrypt_blob(encrypted_block, file_key, IV_SIZE, TAG_SIZE, {}, decrypted_block)) {
                    memcpy(plain_block.data(), decrypted_block.data(), decrypted_block.size());
                }
            }
        }
        
        size_t to_write = min(remaining_size, PLAINTEXT_BLOCK_SIZE - offset_in_block);
        memcpy(plain_block.data() + offset_in_block, buf + total_written, to_write);
        
        size_t current_plain_block_size = offset_in_block + to_write;
        if (current_plain_block_size > PLAINTEXT_BLOCK_SIZE) {
            current_plain_block_size = PLAINTEXT_BLOCK_SIZE;
        }
        vector<uint8_t> final_plain_block(plain_block.begin(), plain_block.begin() + current_plain_block_size);


        vector<uint8_t> iv(IV_SIZE), ct, tag;
        if (RAND_bytes(iv.data(), (int)iv.size()) != 1) return -EIO;
        if (!aes256_gcm_encrypt_blob(final_plain_block, file_key, iv, {}, ct, tag)) return -EIO;

        vector<uint8_t> out_blob;
        out_blob.insert(out_blob.end(), iv.begin(), iv.end());
        out_blob.insert(out_blob.end(), ct.begin(), ct.end());
        out_blob.insert(out_blob.end(), tag.begin(), tag.end());

        iofs.seekp(cipher_block_offset, ios::beg);
        iofs.write(reinterpret_cast<const char*>(out_blob.data()), out_blob.size());

        total_written += to_write;
        current_offset += to_write;
        remaining_size -= to_write;
    }
    
    std::lock_guard<std::mutex> lock(g_state_mutex);
    auto it = GSTATE.pt_map.find(p);
    if (it != GSTATE.pt_map.end()) {
        uint64_t new_size = offset + size;
        if (new_size > it->second.size) {
            it->second.size = new_size;
            FileHeader header = {FILE_HEADER_MAGIC, new_size};
            write_file_header(cpath, header);
        }
    }
    
    return total_written;
}

int lz_unlink(const char *path) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    string p(path);
    if (!p.empty() && p[0] == '/') p = p.substr(1);
    auto it = GSTATE.pt_map.find(p);
    if (it == GSTATE.pt_map.end()) return -ENOENT;
    
    fs::path cpath = fs::path(GSTATE.enc_dir) / it->second.cipher;
    fs::remove(cpath);
    
    GSTATE.ct_to_pt.erase(it->second.cipher);
    GSTATE.pt_map.erase(it);
    
    return 0;
}

int lz_release(const char *path, struct fuse_file_info *fi) {
    (void)path; (void)fi;
    return 0;
}

int lz_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void)fi;
    string p(path);
    if (p.size() && p[0] == '/') p = p.substr(1);
    
    fs::path cpath;
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto it = GSTATE.pt_map.find(p);
        if (it == GSTATE.pt_map.end()) return -ENOENT;
        cpath = fs::path(GSTATE.enc_dir) / it->second.cipher;

        it->second.size = size;
    }
    

    FileHeader header = {FILE_HEADER_MAGIC, (uint64_t)size};
    if (!write_file_header(cpath, header)) return -EIO;


    size_t num_blocks = (size + PLAINTEXT_BLOCK_SIZE - 1) / PLAINTEXT_BLOCK_SIZE;
    if (size == 0) num_blocks = 0;
    size_t new_cipher_size = FILE_HEADER_SIZE + num_blocks * CIPHERTEXT_BLOCK_SIZE;

    std::error_code ec;
    fs::resize_file(cpath, new_cipher_size, ec);
    if (ec) return -EIO;

    return 0;
}
