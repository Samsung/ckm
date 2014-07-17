#pragma once

#include <string>

#include <safe-buffer.h>

#include <ckm/ckm-type.h>
#include <protocols.h>

namespace CKM {
    struct DBRow {
        std::string alias;
        std::string smackLabel;
        int restricted;
        int exportable;
        DBDataType dataType;        // cert/key/data
        DBCMAlgType algorithmType;  // Algorithm type used for row data encryption
        int encryptionScheme;       // for example: (ENCR_BASE64 | ENCR_PASSWORD)
        SafeBuffer iv;               // encoded in base64
        int dataSize;               // size of information without hash and padding
        SafeBuffer data;
    };
} // namespace CKM


