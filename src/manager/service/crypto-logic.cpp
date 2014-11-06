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
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ckm/ckm-error.h>

#include <dpl/log/log.h>

#include <base64.h>
#include <digest.h>
#include <crypto.h>
#include <crypto-logic.h>

#define AES_CBC_KEY_SIZE 32

namespace CKM {

CryptoLogic::CryptoLogic(){}

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
        ThrowMsg(Exception::InternalError, "Empty smack label.");
    }
    if (applicationKey.size() == 0) {
        ThrowMsg(Exception::InternalError, "Empty application key.");
    }
    if (haveKey(smackLabel)) {
        ThrowMsg(Exception::InternalError, "Application key for " << smackLabel
                 << "label already exists.");
    }
    m_keyMap[smackLabel] = applicationKey;
}

RawBuffer CryptoLogic::encryptDataAesCbc(
    const RawBuffer &data,
    const RawBuffer &key,
    const RawBuffer &iv) const
{
    Crypto::Cipher::AesCbcEncryption enc(key, iv);
    RawBuffer result = enc.Append(data);
    RawBuffer tmp = enc.Finalize();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(result));
    return result;
}

RawBuffer CryptoLogic::decryptDataAesCbc(
    const RawBuffer &data,
    const RawBuffer &key,
    const RawBuffer &iv) const
{
    Crypto::Cipher::AesCbcDecryption dec(key, iv);
    RawBuffer result = dec.Append(data);
    RawBuffer tmp = dec.Finalize();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(result));
    return result;
}

std::pair<RawBuffer,RawBuffer> CryptoLogic::encryptDataAesGcm(
    const RawBuffer &data,
    const RawBuffer &key,
    const RawBuffer &iv) const
{
    RawBuffer tag(AES_GCM_TAG_SIZE);
    Crypto::Cipher::AesGcmEncryption enc(key, iv);
    RawBuffer result = enc.Append(data);
    RawBuffer tmp = enc.Finalize();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(result));
    if (0 == enc.Control(EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag.data())) {
        LogError("Error in aes control function. Get tag failed.");
        ThrowMsg(Exception::EncryptDBRowError, "Error in aes control function. Get tag failed.");
    }
    return std::make_pair(result, tag);
}

RawBuffer CryptoLogic::decryptDataAesGcm(
    const RawBuffer &data,
    const RawBuffer &key,
    const RawBuffer &iv,
    const RawBuffer &tag) const
{
    Crypto::Cipher::AesGcmDecryption dec(key, iv);
    if (tag.size() < AES_GCM_TAG_SIZE) {
        LogError("Error in decryptDataAesGcm. Tag is too short.");
        ThrowMsg(Exception::DecryptDBRowError, "Error in decryptDataAesGcm. Tag is too short");
    }
    void *ptr = (void*)tag.data();
    if (0 == dec.Control(EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, ptr)) {
        LogError("Error in aes control function. Set tag failed.");
        ThrowMsg(Exception::DecryptDBRowError, "Error in aes control function. Set tag failed.");
    }
    RawBuffer result = dec.Append(data);
    RawBuffer tmp = dec.Finalize();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(result));
    return result;
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
        ThrowMsg(Exception::InternalError, "PCKS5_PKKDF_HMAC_SHA1 failed.");
    }
    return result;
}

RawBuffer CryptoLogic::generateRandIV() const {
    RawBuffer civ(EVP_MAX_IV_LENGTH);

    if (1 != RAND_bytes(civ.data(), civ.size())) {
        ThrowMsg(Exception::InternalError,
          "RAND_bytes failed to generate IV.");
    }

    return civ;
}

void CryptoLogic::encryptRow(const Password &password, DBRow &row)
{
    try {
        DBRow crow = row;
        RawBuffer key;
        RawBuffer result1;
        RawBuffer result2;

        crow.algorithmType = DBCMAlgType::AES_GCM_256;
        crow.dataSize = crow.data.size();

        if (crow.dataSize <= 0) {
            ThrowMsg(Exception::EncryptDBRowError, "Invalid dataSize.");
        }

        if (!haveKey(row.ownerLabel)) {
            ThrowMsg(Exception::EncryptDBRowError, "Missing application key for " <<
              row.ownerLabel << " label.");
        }

        if (crow.iv.empty()) {
            crow.iv = generateRandIV();
        }

        key = m_keyMap[row.ownerLabel];
        crow.encryptionScheme = ENCR_APPKEY;

        auto dataPair = encryptDataAesGcm(crow.data, key, crow.iv);
        crow.data = dataPair.first;
        crow.tag = dataPair.second;

        if (!password.empty()) {
            key = passwordToKey(password, crow.iv, AES_CBC_KEY_SIZE);
            crow.data = encryptDataAesCbc(crow.data, key, crow.iv);
            crow.encryptionScheme |= ENCR_PASSWORD;
        }

        encBase64(crow.data);
        crow.encryptionScheme |= ENCR_BASE64;
        encBase64(crow.iv);

        row = crow;
    } catch(const CKM::Base64Encoder::Exception::Base &e) {
        LogDebug("Base64Encoder error: " << e.GetMessage());
        ThrowMsg(Exception::Base64EncoderError, e.GetMessage());
    } catch(const CKM::Base64Decoder::Exception::Base &e) {
        LogDebug("Base64Encoder error: " << e.GetMessage());
        ThrowMsg(Exception::Base64DecoderError, e.GetMessage());
    } catch(const CKM::Crypto::Exception::Base &e) {
        LogDebug("Crypto error: " << e.GetMessage());
        ThrowMsg(Exception::EncryptDBRowError, e.GetMessage());
    }
}

void CryptoLogic::decryptRow(const Password &password, DBRow &row)
{
    try {
        DBRow crow = row;
        RawBuffer key;
        RawBuffer digest, dataDigest;

        if (row.algorithmType != DBCMAlgType::AES_GCM_256) {
            ThrowMsg(Exception::DecryptDBRowError, "Invalid algorithm type.");
        }

        if ((row.encryptionScheme & ENCR_PASSWORD) && password.empty()) {
            ThrowMsg(Exception::DecryptDBRowError,
              "DB row is password protected, but given password is "
              "empty.");
        }

        if ((row.encryptionScheme & ENCR_APPKEY) && !haveKey(row.ownerLabel)) {
            ThrowMsg(Exception::DecryptDBRowError, "Missing application key for " <<
              row.ownerLabel << " label.");
        }

        decBase64(crow.iv);
        if (crow.encryptionScheme & ENCR_BASE64) {
            decBase64(crow.data);
        }

        if (crow.encryptionScheme & ENCR_PASSWORD) {
            key = passwordToKey(password, crow.iv, AES_CBC_KEY_SIZE);
            crow.data = decryptDataAesCbc(crow.data, key, crow.iv);
        }

        if (crow.encryptionScheme & ENCR_APPKEY) {
            key = m_keyMap[crow.ownerLabel];
            crow.data = decryptDataAesGcm(crow.data, key, crow.iv, crow.tag);
        }

        if (static_cast<int>(crow.data.size()) < crow.dataSize) {
            ThrowMsg(Exception::DecryptDBRowError,
                "Decrypted row size mismatch");
            LogError("Decryption row size mismatch");
        }

        if (static_cast<int>(crow.data.size()) > crow.dataSize) {
            crow.data.resize(crow.dataSize);
        }

        row = crow;
    } catch(const CKM::Base64Encoder::Exception::Base &e) {
        LogDebug("Base64Encoder error: " << e.GetMessage());
        ThrowMsg(Exception::Base64EncoderError, e.GetMessage());
    } catch(const CKM::Base64Decoder::Exception::Base &e) {
        LogDebug("Base64Encoder error: " << e.GetMessage());
        ThrowMsg(Exception::Base64DecoderError, e.GetMessage());
    } catch(const CKM::Crypto::Exception::Base &e) {
        LogDebug("Crypto error: " << e.GetMessage());
        ThrowMsg(Exception::DecryptDBRowError, e.GetMessage());
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
        ThrowMsg(Exception::Base64EncoderError, "Base64Encoder returned empty data.");
    }

    data = std::move(encdata);
}

void CryptoLogic::decBase64(RawBuffer &data)
{
    Base64Decoder bdec;
    RawBuffer decdata;

    bdec.reset();
    bdec.append(data);
    if (not bdec.finalize()) {
        ThrowMsg(Exception::Base64DecoderError,
          "Failed in Base64Decoder.finalize.");
    }

    decdata = bdec.get();

    if (decdata.size() == 0) {
        ThrowMsg(Exception::Base64DecoderError, "Base64Decoder returned empty data.");
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

