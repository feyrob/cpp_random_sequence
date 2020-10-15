// map every uint64_t to a (seemingly) random other uint64_t uniquely
//
// the mapping is done by encrypting the uint64_t as a single blowfish block
//
// CC0 copyright
// https://creativecommons.org/publicdomain/zero/1.0/
 
#include <iostream>
 
#include <iomanip>
#include <cstdint>
#include <chrono>
 
#include <cryptopp/sha.h>
 
#include <cryptopp/modes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
 
using namespace std;
using namespace std::chrono;
using namespace CryptoPP;
 
 
string to_hexstr(byte const* const block, size_t length){
    string hex_str;
    ArraySource( block, length, true,
        new HexEncoder(
            new StringSink( hex_str)
        ) 
    ); 
    return hex_str;
}
 
uint64_t to_random(
    ECB_Mode<Blowfish>::Encryption& e,
    uint64_t in
){
            byte* plain_block = (byte*)&in;
            byte cipher_block[Blowfish::BLOCKSIZE];
 
            // thing being timed
            ArraySource(
                plain_block,
                Blowfish::BLOCKSIZE,
                true, 
                new StreamTransformationFilter(
                    e,
                    new ArraySink(
                        cipher_block, 
                        Blowfish::BLOCKSIZE
                    )
                )
            ); 
            uint64_t result = *((uint64_t*)cipher_block);
            return result;
}
 
void f0(){
    SecByteBlock key(Blowfish::DEFAULT_KEYLENGTH);
    {
        for(int i = 0; i<Blowfish::DEFAULT_KEYLENGTH; i++){
            key[i] = byte(0);
        }
    }
    ECB_Mode<Blowfish>::Encryption e;
    e.SetKey(key, key.size());
 
    cout << "1 -> " << to_random(e, 1) << endl;
 
}
 
int main(int argc, char** argv){
    f0();
    //blowfish_benchmark();
    return 0;
}
