#pragma once

#include <ckm/ckm-type.h>
#include <protocols.h>

namespace CKM {
    struct DBRow {
        Name name;
        Label smackLabel;
        int exportable;
        DBDataType dataType;        // cert/key/data
        DBCMAlgType algorithmType;  // Algorithm type used for row data encryption
        int encryptionScheme;       // for example: (ENCR_BASE64 | ENCR_PASSWORD)
        RawBuffer iv;               // encoded in base64
        int dataSize;               // size of information without hash and padding
        RawBuffer data;
        RawBuffer tag;              // tag for Aes Gcm algorithm
    };
} // namespace CKM

