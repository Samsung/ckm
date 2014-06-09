#pragma once

#include <string>

#include <ckm/ckm-type.h>
#include <protocols.h>

namespace CKM {
    struct DBRow {
        std::string alias;
        std::string smackLabel;
        int restricted;
        int exportable;
        DBDataType dataType;        // cert/key/data
        int algorithmType;          // AES mode ?
        int encryptionScheme;       // for example: (ENCR_BASE64 | ENCR_PASSWORD)
        RawBuffer iv;               // encoded in base64
        int dataSize;               // size of information without hash and padding
        RawBuffer data;
    };
} // namespace CKM


