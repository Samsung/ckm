#include <test_common.h>
#include <iostream>

using namespace CKM;

RawBuffer createDefaultPass() {
    RawBuffer raw;
    for(unsigned char i =0; i < RAW_PASS_SIZE; i++)
        raw.push_back(i);
    return raw;
}

RawBuffer createBigBlob(std::size_t size) {
    RawBuffer raw;
    for(std::size_t i = 0; i < size; i++) {
        raw.push_back(static_cast<unsigned char>(i));
    }
    return raw;
}

//raw to hex string conversion from SqlConnection
std::string rawToHexString(const std::vector<unsigned char> &raw) {
    std::string dump(raw.size()*2, '0');
    for(std::size_t i = 0; i < raw.size(); i++){
        sprintf(&dump[2*i], "%02x", raw[i]);
    }
    return dump;
}

