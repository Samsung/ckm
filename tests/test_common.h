#pragma once
#include <string>
#include <ckm/ckm-type.h>

// mirrors the API-defined value
#ifndef AES_GCM_TAG_SIZE
#define AES_GCM_TAG_SIZE 16
#endif

CKM::RawBuffer createDefaultPass();
CKM::RawBuffer createBigBlob(std::size_t size);

const CKM::RawBuffer defaultPass = createDefaultPass();
const std::string pattern =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const std::size_t RAW_PASS_SIZE = 32;
const std::size_t HEX_PASS_SIZE = RAW_PASS_SIZE * 2;


std::string rawToHexString(const CKM::RawBuffer &raw);
