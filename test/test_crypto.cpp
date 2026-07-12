#include <iostream>
#include <vector>
#include "securelettuce/openvault/crypto/crypto.h"
#include "securelettuce/openvault/crypto/states.h"
#include <openssl/rand.h>
using namespace std;

State GSTATE;
std::mutex g_state_mutex;

int main() {
    vector<uint8_t> mk(32, 1);
    vector<uint8_t> iv(12, 2);
    vector<uint8_t> pt = { 'h', 'e', 'l', 'l', 'o' };
    vector<uint8_t> ct, tag;
    aes256_gcm_encrypt_blob(pt, mk, iv, {}, ct, tag);
    
    vector<uint8_t> blob;
    blob.insert(blob.end(), iv.begin(), iv.end());
    blob.insert(blob.end(), ct.begin(), ct.end());
    blob.insert(blob.end(), tag.begin(), tag.end());
    
    // Now pad with zeros to simulate reading less than a full block without resize
    blob.resize(4124, 0);
    
    vector<uint8_t> out;
    bool ok = aes256_gcm_decrypt_blob(blob, mk, 12, 16, {}, out);
    cout << "Decrypt padded blob: " << ok << endl;
    return 0;
}
