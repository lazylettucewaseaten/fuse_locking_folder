#include "crypto.h"
#include "states.h" 

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

using namespace std;
using namespace nlohmann;

bool aes256_gcm_encrypt_blob(
    const vector<uint8_t>& plaintext,
    const vector<uint8_t>& key,
    const vector<uint8_t>& iv,
    const vector<uint8_t>& aad,
    vector<uint8_t>& ciphertext_out,
    vector<uint8_t>& tag_out
) {
    if (key.size() != 32) {
        cerr << "[ERROR] Key size must be 32 bytes\n";
        return false;
    }
    if (iv.empty()) {
        cerr << "[ERROR] IV empty\n";
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int ciphertext_len = 0;
    ciphertext_out.resize(plaintext.size());

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) goto err;

    if (!aad.empty()) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad.data(), (int)aad.size())) goto err;
    }

    if (!plaintext.empty()) {
        if (1 != EVP_EncryptUpdate(ctx, ciphertext_out.data(), &len, plaintext.data(), (int)plaintext.size())) goto err;
        ciphertext_len = len;
    } else {
        ciphertext_len = 0;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext_out.data() + ciphertext_len, &len)) goto err;
    ciphertext_len += len;
    ciphertext_out.resize(ciphertext_len);

    tag_out.resize(16);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_out.size(), tag_out.data())) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return true;

err:
    EVP_CIPHER_CTX_free(ctx);
    cerr << "[ERROR] AES-256-GCM encryption failed\n";
    return false;
}

bool aes256_gcm_decrypt_blob(const std::vector<uint8_t>& blob,
                             const std::vector<uint8_t>& key,
                             int iv_len, int tag_len,
                             const std::vector<uint8_t>& aad,
                             std::vector<uint8_t>& plaintxt_out) {
    if (key.size() != 32) {
        std::cerr << "[DEBUG] Key size is not 32 bytes, it is " << key.size() << std::endl;
        return false;
    }
    if ((int)blob.size() < iv_len + tag_len) {
        std::cerr << "[DEBUG] Blob too small: " << blob.size() << " need >= " << iv_len + tag_len << std::endl;
        return false;
    }

    const uint8_t* iv = blob.data();
    const uint8_t* ct = blob.data() + iv_len;
    size_t ct_len = blob.size() - iv_len - tag_len;
    const uint8_t* tag = blob.data() + iv_len + ct_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    int outlen = 0, outlen_total = 0, tmplen = 0;


    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv) != 1) goto cleanup;

    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, NULL, &outlen, aad.data(), (int)aad.size()) != 1) goto cleanup;
    }

    plaintxt_out.resize(ct_len);
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintxt_out.data(), &outlen, ct, (int)ct_len) != 1) goto cleanup;
        outlen_total += outlen;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag) != 1) goto cleanup;

    if (EVP_DecryptFinal_ex(ctx, plaintxt_out.data() + outlen_total, &tmplen) != 1) {
        std::cerr << "[DEBUG] EVP_DecryptFinal_ex failed: authentication tag mismatch\n";
        goto cleanup;
    }
    outlen_total += tmplen;
    plaintxt_out.resize(outlen_total);
    ok = true;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

vector<uint8_t> base64Decode(const string &in) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf(in.data(), (int)in.size());
    bio = BIO_push(b64, bio);
    vector<uint8_t> out;
    out.resize((in.size() * 3) / 4 + 8);
    int len = BIO_read(bio, out.data(), (int)out.size());
    if (len <= 0) { out.clear(); }
    else out.resize(len);
    BIO_free_all(bio);
    return out;
}

string base64Encode(const vector<uint8_t> &data) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, data.data(), (int)data.size());
    BIO_flush(bio);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    string s(bptr->data, bptr->length);
    BIO_free_all(bio);
    return s;
}

string base64UrlToStd(const string &s) {
    string t = s;
    for (char &c : t) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (t.size() % 4) t.push_back('=');
    return t;
}

string base64StdToUrl(string s) {
    for (char &c : s) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}

vector<uint8_t> derive_file_key(const string& path) {
    vector<uint8_t> derived_key(32);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return {};

    if (EVP_PKEY_derive_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, reinterpret_cast<const unsigned char *>("lazylocking-salt"), 16) <= 0) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, GSTATE.MK.data(), GSTATE.MK.size()) <= 0) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>( path.c_str()), path.length()) <= 0) { EVP_PKEY_CTX_free(pctx); return {}; }

    size_t out_len = 32;
    if (EVP_PKEY_derive(pctx, derived_key.data(), &out_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    EVP_PKEY_CTX_free(pctx);
    return derived_key;
}


vector<uint8_t>derivekeyscrypt(const string &password,vector<uint8_t>&salt,uint64_t N ,uint64_t r,uint64_t p,vector<uint8_t>&data,int keyLen ){
    // vector<uint8_t>data(keyLen);
    data.resize(keyLen);
    if (EVP_PBE_scrypt(password.c_str(), password.size(),
                       salt.data(), salt.size(),
                       N, r, p, 0x7fffffff,   // 0 no memory limit
                       data.data(), keyLen) != 1) {
        throw std::runtime_error("EVP_PBE_scrypt failed");
    }

    return data;
}



bool decrypting_master_key(const string &conf_path,const string &password, vector<uint8_t> &masterKeyOut) {
    ifstream ifs(conf_path);
    if (!ifs.is_open()) {
        cerr << "[DEBUG] Cannot open conf: " << conf_path << "\n";
        return false;
    }

    json j;
    try { ifs >> j; }
    catch(...) { cerr << "[DEBUG] Failed to parse JSON conf\n"; return false; }

    if (!j.contains("EncryptedKey") || !j.contains("Salt") || !j.contains("IV") || !j.contains("TAG")) {
        cerr << "[DEBUG] JSON missing EncryptedKey, Salt, IV, or TAG\n";
        return false;
    }

    auto base64DecodeB64Url = [](const string &s){
        string tmp = base64UrlToStd(s);
        return base64Decode(tmp);
    };

    vector<uint8_t> ciphertext = base64DecodeB64Url(j["EncryptedKey"].get<string>());
    vector<uint8_t> salt = base64DecodeB64Url(j["Salt"].get<string>());
    vector<uint8_t> iv   = base64DecodeB64Url(j["IV"].get<string>());
    vector<uint8_t> tag  = base64DecodeB64Url(j["TAG"].get<string>());

    int keylen = 32,N,r,p;
    if (j.contains("KDF") && j["KDF"].is_object()) {
        // if (j["KDF"].contains("Iterations")) iterations = j["KDF"]["Iterations"].get<int>();
        if (j["ScryptObject"].contains("KeyLen")) keylen = j["ScryptObject"]["KeyLen"].get<int>();
        if (j["ScryptObject"].contains("N")) N = j["ScryptObject"]["N"].get<int>();
        if (j["ScryptObject"].contains("R")) r = j["ScryptObject"]["R"].get<int>();
        if (j["ScryptObject"].contains("P")) p = j["ScryptObject"]["P"].get<int>();
    }

    vector<uint8_t> derived(keylen);


    try{
        derivekeyscrypt(password,salt,N,r,p,derived,keylen);
    }
    catch(const std::exception& e){
        cerr << "[DEBUG] Key derivation failed\n";
        std::cerr << e.what() << '\n';
    }
    
    // int pbkdf2_res = PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
    //                                     salt.data(), (int)salt.size(),
    //                                     iterations, EVP_sha512(), keylen, derived.data());




    // EncryptedKey stored as IV||CT||TAG - reconstruct that
    vector<uint8_t> encBlob;
    encBlob.insert(encBlob.end(), iv.begin(), iv.end());
    encBlob.insert(encBlob.end(), ciphertext.begin(), ciphertext.end());
    encBlob.insert(encBlob.end(), tag.begin(), tag.end());

    vector<uint8_t> mk;
    if (!aes256_gcm_decrypt_blob(encBlob, derived, (int)iv.size(), (int)tag.size(), {}, mk)) {
        fill(derived.begin(), derived.end(), 0);
        cerr << "[DEBUG] Decryption failed: wrong password or corrupt conf\n";
        return false;
    }
    fill(derived.begin(), derived.end(), 0);
    masterKeyOut.swap(mk);
    return true;
}
