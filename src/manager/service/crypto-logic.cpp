/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 * @file        crypto-logic.cpp
 * @author      Sebastian Grabowski (s.grabowski@samsung.com)
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Crypto module implementation.
 */

#include <iostream>
#include <fstream>
#include <utility>
#include <climits>

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ckm/ckm-error.h>

#include <dpl/log/log.h>

#include <base64.h>
#include <digest.h>
#include <crypto-logic.h>

#include <generic-backend/exception.h>
#include <sw-backend/internals.h>

namespace CKM {

namespace {

const static int AES_CBC_KEY_SIZE = 32;
const static int AES_GCM_TAG_SIZE = 16;

// Encryption scheme flags (enable/disable specific encryption type, multiple choice)
const int ENCR_BASE64 =   1 << 0;
const int ENCR_APPKEY =   1 << 1;
const int ENCR_PASSWORD = 1 << 2;

// Encryption order flags (single choice)
const int ENCR_ORDER_OFFSET = 24;
const int ENCR_ORDER_FILTER = INT_MAX << ENCR_ORDER_OFFSET; // 0xff000000
const int ENCR_ORDER_CLEAR = ~ENCR_ORDER_FILTER; // 0x00ffffff
/*
 * ENCR_ORDER_V1 - v1 encryption order. Token returned from store is encrypted with app key and
 * optionally by custom user password. In such form it is stored in db.
 */
const int ENCR_ORDER_V1 = CryptoLogic::ENCRYPTION_V1 << ENCR_ORDER_OFFSET;
/*
 * ENCR_ORDER_V2 - v2 encryption order. Stored data is optionally encrypted by store with
 * user password. Returned token is encrypted with app key and stored in db.
 */
const int ENCR_ORDER_V2 = CryptoLogic::ENCRYPTION_V2 << ENCR_ORDER_OFFSET;

} // anonymous namespace

CryptoLogic::CryptoLogic() {}

CryptoLogic::CryptoLogic(CryptoLogic &&second) {
    m_keyMap = std::move(second.m_keyMap);
}

CryptoLogic& CryptoLogic::operator=(CryptoLogic &&second) {
    if (this == &second)
        return *this;
    m_keyMap = std::move(second.m_keyMap);
    return *this;
}

bool CryptoLogic::haveKey(const Label &smackLabel)
{
    return (m_keyMap.count(smackLabel) > 0);
}

void CryptoLogic::pushKey(const Label &smackLabel,
                          const RawBuffer &applicationKey)
{
    if (smackLabel.length() == 0) {
        ThrowErr(Exc::InternalError, "Empty smack label.");
    }
    if (applicationKey.size() == 0) {
        ThrowErr(Exc::InternalError, "Empty application key.");
    }
    if (haveKey(smackLabel)) {
        ThrowErr(Exc::InternalError, "Application key for ", smackLabel,
            "label already exists.");
    }

    m_keyMap[smackLabel] = applicationKey;
}

void CryptoLogic::removeKey(const Label &smackLabel)
{
    m_keyMap.erase(smackLabel);
}

RawBuffer CryptoLogic::passwordToKey(
    const Password &password,
    const RawBuffer &salt,
    size_t keySize) const
{
    RawBuffer result(keySize);

    if (1 != PKCS5_PBKDF2_HMAC_SHA1(
                password.c_str(),
                password.size(),
                salt.data(),
                salt.size(),
                1024,
                result.size(),
                result.data()))
    {
        ThrowErr(Exc::InternalError, "PCKS5_PKKDF_HMAC_SHA1 failed.");
    }

    return result;
}

RawBuffer CryptoLogic::generateRandIV() const {
    RawBuffer civ(EVP_MAX_IV_LENGTH);

    if (1 != RAND_bytes(civ.data(), civ.size())) {
        ThrowErr(Exc::InternalError, "RAND_bytes failed to generate IV.");
    }

    return civ;
}

void CryptoLogic::encryptRow(DB::Row &row)
{
    try {
        DB::Row crow = row;
        RawBuffer key;
        RawBuffer result1;
        RawBuffer result2;

        crow.algorithmType = DBCMAlgType::AES_GCM_256;
        crow.dataSize = crow.data.size();

        if (crow.dataSize <= 0) {
            ThrowErr(Exc::InternalError, "Invalid dataSize.");
        }

        if (!haveKey(row.ownerLabel)) {
            ThrowErr(Exc::InternalError, "Missing application key for ",
              row.ownerLabel, " label.");
        }

        if (crow.iv.empty()) {
            crow.iv = generateRandIV();
        }

        key = m_keyMap[row.ownerLabel];
        crow.encryptionScheme = ENCR_APPKEY;

        auto dataPair = Crypto::SW::Internals::encryptDataAesGcm(key, crow.data, crow.iv, AES_GCM_TAG_SIZE);
        crow.data = dataPair.first;

        crow.tag = dataPair.second;

        encBase64(crow.data);
        crow.encryptionScheme |= ENCR_BASE64;
        encBase64(crow.iv);

        crow.encryptionScheme &= ENCR_ORDER_CLEAR;
        crow.encryptionScheme |= ENCR_ORDER_V2;

        row = std::move(crow);
    } catch(const CKM::Base64Encoder::Exception::Base &e) {
        ThrowErr(Exc::InternalError, e.GetMessage());
    } catch(const CKM::Base64Decoder::Exception::Base &e) {
        ThrowErr(Exc::InternalError, e.GetMessage());
    }
}

int CryptoLogic::getSchemeVersion(int encryptionScheme)
{
    return encryptionScheme >> ENCR_ORDER_OFFSET;
}

void CryptoLogic::decryptRow(const Password &password, DB::Row &row)
{
    try {
        DB::Row crow = row;
        RawBuffer key;
        RawBuffer digest, dataDigest;

        if (row.algorithmType != DBCMAlgType::AES_GCM_256) {
            ThrowErr(Exc::AuthenticationFailed, "Invalid algorithm type.");
        }

        if ((row.encryptionScheme & ENCR_PASSWORD) && password.empty()) {
            ThrowErr(Exc::AuthenticationFailed,
              "DB row is password protected, but given password is "
              "empty.");
        }

        if ((row.encryptionScheme & ENCR_APPKEY) && !haveKey(row.ownerLabel)) {
            ThrowErr(Exc::AuthenticationFailed, "Missing application key for ",
              row.ownerLabel, " label.");
        }

        decBase64(crow.iv);
        if (crow.encryptionScheme & ENCR_BASE64) {
            decBase64(crow.data);
        }

        if((crow.encryptionScheme >> ENCR_ORDER_OFFSET) == ENCR_ORDER_V2) {
            if (crow.encryptionScheme & ENCR_APPKEY) {
                key = m_keyMap[crow.ownerLabel];
                crow.data = Crypto::SW::Internals::decryptDataAesGcm(key, crow.data, crow.iv, crow.tag);
            }
        } else {
            if (crow.encryptionScheme & ENCR_PASSWORD) {
                key = passwordToKey(password, crow.iv, AES_CBC_KEY_SIZE);
                crow.data = Crypto::SW::Internals::decryptDataAes(AlgoType::AES_CBC, key, crow.data, crow.iv);
            }

            if (crow.encryptionScheme & ENCR_APPKEY) {
                key = m_keyMap[crow.ownerLabel];
                crow.data = Crypto::SW::Internals::decryptDataAesGcm(key, crow.data, crow.iv, crow.tag);
            }
        }
        if (static_cast<int>(crow.data.size()) < crow.dataSize) {
            ThrowErr(Exc::AuthenticationFailed, "Decrypted row size mismatch");
        }

        if (static_cast<int>(crow.data.size()) > crow.dataSize) {
            crow.data.resize(crow.dataSize);
        }

        row = std::move(crow);
    } catch(const CKM::Base64Encoder::Exception::Base &e) {
        ThrowErr(Exc::InternalError, e.GetMessage());
    } catch(const CKM::Base64Decoder::Exception::Base &e) {
        ThrowErr(Exc::InternalError, e.GetMessage());
    } catch(const Exc::Exception &e) {
        ThrowErr(Exc::AuthenticationFailed, e.message());
    }
}

void CryptoLogic::encBase64(RawBuffer &data)
{
    Base64Encoder benc;
    RawBuffer encdata;

    benc.append(data);
    benc.finalize();
    encdata = benc.get();

    if (encdata.size() == 0) {
        ThrowErr(Exc::InternalError, "Base64Encoder returned empty data.");
    }

    data = std::move(encdata);
}

void CryptoLogic::decBase64(RawBuffer &data)
{
    Base64Decoder bdec;
    RawBuffer decdata;

    bdec.reset();
    bdec.append(data);
    if (!bdec.finalize()) {
        ThrowErr(Exc::InternalError, "Failed in Base64Decoder.finalize.");
    }

    decdata = bdec.get();

    if (decdata.size() == 0) {
        ThrowErr(Exc::InternalError, "Base64Decoder returned empty data.");
    }

    data = std::move(decdata);
}

bool CryptoLogic::equalDigests(RawBuffer &dig1, RawBuffer &dig2)
{
    unsigned int dlen = Digest().length();

    if ((dig1.size() != dlen) || (dig2.size() != dlen))
        return false;
    return (dig1 == dig2);
}

} // namespace CKM

