#include <test_common.h>
#include <iostream>

using namespace CKM;

SafeBuffer createDefaultPass() {
    SafeBuffer raw;
    for(unsigned char i =0; i < RAW_PASS_SIZE; i++)
        raw.push_back(i);
    return raw;
}

SafeBuffer createBigBlob(std::size_t size) {
    SafeBuffer raw;
    for(std::size_t i = 0; i < size; i++) {
        raw.push_back(static_cast<unsigned char>(i));
    }
    return raw;
}

