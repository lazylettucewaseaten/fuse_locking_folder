// main.cpp
#include "crypto/states.h"
#include "crypto/crypto.h"
#include "filesystem/fuse_op.h"

#include <iostream>
#include <filesystem>
#include <fstream>
#include <unistd.h> // For getpass
#include <string.h> // For memset
#include <nlohmann/json.hpp>

using namespace std;
using namespace nlohmann;

// --- Global State & Mutex Definitions ---
State GSTATE;
std::mutex g_state_mutex;

// --- FUSE Operations Struct Definition ---
// This struct maps our functions to the FUSE operation names.
// It is defined globally and initialized within main().
struct fuse_operations lz_oper;


int main(int argc,char *argv[]){
    // Assign FUSE operations to the struct
    lz_oper.getattr    = lz_getattr;
    lz_oper.readdir    = lz_readdir;
    lz_oper.open       = lz_open;
    lz_oper.create     = lz_create;
    lz_oper.read       = lz_read;
    lz_oper.write      = lz_write;
    lz_oper.release    = lz_release;
    lz_oper.unlink     = lz_unlink;
    lz_oper.truncate   = lz_truncate;

    if(argc<3){
        cerr<<"Wrong usage: unlock <vault-dir> <mountpoint>\n";
        return 1;
    }

    string vault = argv[1];
    string mountpoint = argv[2];
    GSTATE.enc_dir = vault;

    string confp = (filesystem::path(GSTATE.enc_dir) / "lazylocking.conf").string();
    if (!filesystem::exists(confp)) {
        cerr << "Missing lazylocking.conf in " << GSTATE.enc_dir << "\n";
        return 1;
    }

    char *pw = getpass("Enter password: ");
    if (!pw) {
        cerr << "Failed to read password\n";
        return 1;
    }
    string password(pw);
    memset(pw, 0, strlen(pw));

    vector<uint8_t> mk;
    if (!decrypting_master_key(confp, password, mk)) {
        cerr << "Wrong password or corrupt conf\n";
        return 1;
    }
    cout << "Successful login\n";
    GSTATE.MK = mk;
    fill(mk.begin(), mk.end(), 0);

    ifstream ifs(confp);
    json j; ifs >> j;
    if (j.contains("IVLen")) GSTATE.iv_len = j["IVLen"].get<int>();
    if (j.contains("TagLen")) GSTATE.tag_len = j["TagLen"].get<int>();

    build_name_map();

    char* fuse_argv[] = {
        argv[0],
        argv[2],
        NULL
    };
    int fuse_argc = 2;

    // The address of the lz_oper struct is passed to fuse_main.
    return fuse_main(fuse_argc, fuse_argv, &lz_oper, NULL);
}
