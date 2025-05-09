#include <iostream>
#include <msgpack.hpp>
#include <cryptlib.h>
#include <osrng.h>
#include <aes.h>
#include <modes.h>
#include <jwt-cpp/jwt.hpp>
#include <chrono>
#include <unordered_map>
#include <websockets/app.h>

using namespace std;
using namespace CryptoPP;

unordered_map<string, chrono::high_resolution_clock::time_point> messageTimestamps;
unordered_map<string, string> authenticatedUsers;

byte key[AES::DEFAULT_KEYLENGTH] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

string encryptedMessage(const string &plainText) {
    string cipherText;
    byte iv[AES::BLOCKSIZE] = {};

    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, sizeof(key), iv);

    StringSource(plainText, true,
                 new StreamTransformationFilter(encryption,
                 new StringSink(cipherText)));

    return cipherText;
}

string decryptedMessage(const string &cipherText) {
    string plainText;
    byte iv[AES::BLOCKSIZE] = {};

    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, sizeof(key), iv);

    StringSource(cipherText, true,
                 new StreamTransformationFilter(decryption,
                 new StringSink(plainText)));

    return plainText;
}

bool validateJWT(const string &token) {
    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs256{"secret"})
                            .with_issuer("auth_server");

        verifier.verify(decoded);
        return true;
    } catch (const exception &e) {
        return false;
    }
}
