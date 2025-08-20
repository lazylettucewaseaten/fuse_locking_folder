// Custom Config Headers
#include "config/conf_main.h"


// Custom Crypto Headers
#include "crypto/crypto.h"
#include "crypto/utilities.h"
#include<string>
#include<stdexcept>
#include<vector>
#include<openssl/buffer.h>
#include <sys/stat.h>
#include<cstdint>
#include<openssl/err.h>
#include<openssl/evp.h>
#include <iostream>
#include <unistd.h>
#include <cstring>



int main(int argc, char* argv[]){
    if(argc<2){
        std::cerr<<"Usage is like this:";
        return 1;
    }

    std::string cmd=argv[1];
    if(cmd=="init"){
        if (argc < 3) {
            std::cerr<<"Usage: "<<argv[0]<<" init [folder]"<<std::endl;
            return 1;
        }   
        std::string foldername=argv[2];
        //run the commands usage is char*
        
        std::vector<uint8_t> masterkey=generateMasterKey();
        
        char *pw=getpass("Enter Password: ");
        if (!pw ) throw std::runtime_error("getpass failed");
        std::string password(pw);
        char *pw2=getpass("Confirm Password:");
        if (!pw2) throw std::runtime_error("getpass failed");
        std::string temp(pw2);
        // cout<<password<<" "<<temp<<std::endl;
        if(password!=temp){
            std::cerr<<"Different passwords\n";
            return 1;
        }
        if(system(("mkdir -p "+foldername).c_str())!=0){
            throw std::runtime_error("File not created ");
        }
        chmod(foldername.c_str(), S_IRWXU);
        std::memset(pw,0,std::strlen(pw));
        std::memset(pw2,0,std::strlen(pw2));

        //why 16 ---?
        std::vector<uint8_t>salt=generatesalt();

        std::vector<uint8_t>derivedkey=derivekey(password,salt,32);
        std::vector<uint8_t>ivout=ivkey(),tagout;
        std::vector<uint8_t>encryptedkey=encryptkey(masterkey,derivedkey,ivout,tagout);

        saveconf(foldername, encryptedkey, salt,ivout,tagout);

        savediriv(foldername,ivout);

        std::cout<<"Master key (store this safely!): "<<base64Encode(masterkey);
        
        OPENSSL_cleanse(masterkey.data(), masterkey.size());
        // fill(masterkey.begin(),masterkey.end(),0);
        OPENSSL_cleanse(derivedkey.data(), derivedkey.size());
        // fill(derivedkey.begin(),derivedkey.end(),0);
        OPENSSL_cleanse(salt.data(), salt.size());
        // fill(salt.begin(),salt.end(),0);
        OPENSSL_cleanse(password.data(), password.size());
        // fill(password.begin(),password.end(),0);
        OPENSSL_cleanse(temp.data(), temp.size());
        // fill(temp.begin(),temp.end(),0);
        return 0;
    }
    std::cerr<<"Incorrect usage"<<std::endl;
    return 1;

}