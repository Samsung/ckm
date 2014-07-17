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

bool CryptoLogic::haveKey(const std::string &smackLabel)
{
    return (m_keyMap.count(smackLabel) > 0);
}

void CryptoLogic::pushKey(const std::string &smackLabel,
                            const SafeBuffer &applicationKey)
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

std::size_t CryptoLogic::insertDigest(SafeBuffer &data, const int dataSize)
{
    SafeBuffer digest;

    try {
        Digest dig;
        dig.append(data, dataSize);
        digest = dig.finalize();
    } catch (Digest::Exception::Base &e) {
        LogError("Failed to calculate digest in insertDigest: " <<
                 e.DumpToString());
        ThrowMsg(Exception::InternalError, e.GetMessage());
    }
    data.insert(data.begin(), digest.begin(), digest.end());
    return digest.size();
}

void CryptoLogic::removeDigest(SafeBuffer &data, SafeBuffer &digest)
{
    unsigned int dlen = Digest().length();

    if (data.size() < dlen) {
        ThrowMsg(Exception::InternalError,
                 "Cannot remove digest: data size mismatch.");
    }

    digest.assign(data.begin(), data.begin() + dlen);
    data.erase(data.begin(), data.begin() + dlen);
}

SafeBuffer CryptoLogic::encryptData(
    const SafeBuffer &data,
    const SafeBuffer &key,
    const SafeBuffer &iv) const
{
    Crypto::Cipher::AesCbcEncryption enc(key, iv);
    SafeBuffer result = enc.Append(data);
    SafeBuffer tmp = enc.Finalize();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(result));
    return result;
}

SafeBuffer CryptoLogic::decryptData(
    const SafeBuffer &data,
    const SafeBuffer &key,
    const SafeBuffer &iv) const
{
    Crypto::Cipher::AesCbcDecryption dec(key, iv);
    SafeBuffer result = dec.Append(data);
    SafeBuffer tmp = dec.Finalize();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(result));
    return result;
}

SafeBuffer CryptoLogic::passwordToKey(
    const std::string &password,
    const SafeBuffer &salt,
    size_t keySize) const
{
    SafeBuffer result(keySize);

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

SafeBuffer CryptoLogic::generateRandIV() const {
    SafeBuffer civ(EVP_MAX_IV_LENGTH);

    if (1 != RAND_bytes(civ.data(), civ.size())) {
        ThrowMsg(Exception::InternalError,
          "RAND_bytes failed to generate IV.");
    }

    return civ;
}

void CryptoLogic::encryptRow(const std::string &password, DBRow &row)
{
    try {
        DBRow crow = row;
        SafeBuffer key;
        SafeBuffer result1;
        SafeBuffer result2;

        crow.algorithmType = DBCMAlgType::AES_CBC_256;

        if (crow.dataSize <= 0) {
            ThrowMsg(Exception::EncryptDBRowError, "Invalid dataSize.");
        }

        if (!haveKey(row.smackLabel)) {
            ThrowMsg(Exception::EncryptDBRowError, "Missing application key for " <<
              row.smackLabel << " label.");
        }

        if (crow.iv.empty()) {
            crow.iv = generateRandIV();
        }

        key = m_keyMap[row.smackLabel];
        crow.encryptionScheme = ENCR_APPKEY;

        insertDigest(crow.data, crow.dataSize);
        crow.data = encryptData(crow.data, key, crow.iv);

        if (!password.empty()) {
            key = passwordToKey(password, crow.iv, AES_CBC_KEY_SIZE);
            crow.data = encryptData(crow.data, key, crow.iv);
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

void CryptoLogic::decryptRow(const std::string &password, DBRow &row)
{
    try {
        DBRow crow = row;
        SafeBuffer key;
        SafeBuffer digest, dataDigest;

        if (row.algorithmType != DBCMAlgType::AES_CBC_256) {
            ThrowMsg(Exception::DecryptDBRowError, "Invalid algorithm type.");
        }

        if ((row.encryptionScheme & ENCR_PASSWORD) && password.empty()) {
            ThrowMsg(Exception::DecryptDBRowError,
              "DB row is password protected, but given password is "
              "empty.");
        }

        if ((row.encryptionScheme & ENCR_APPKEY) && !haveKey(row.smackLabel)) {
            ThrowMsg(Exception::DecryptDBRowError, "Missing application key for " <<
              row.smackLabel << " label.");
        }

        decBase64(crow.iv);
        if (crow.encryptionScheme & ENCR_BASE64) {
            decBase64(crow.data);
        }

        if (crow.encryptionScheme & ENCR_PASSWORD) {
            key = passwordToKey(password, crow.iv, AES_CBC_KEY_SIZE);
            crow.data = decryptData(crow.data, key, crow.iv);
        }

        if (crow.encryptionScheme & ENCR_APPKEY) {
            key = m_keyMap[crow.smackLabel];
            crow.data = decryptData(crow.data, key, crow.iv);
        }

        removeDigest(crow.data, digest);

        if (static_cast<std::size_t>(crow.dataSize) != crow.data.size()) {
            ThrowMsg(Exception::DecryptDBRowError,
              "Decrypted db row data size mismatch.");
        }

        Digest dig;
        dig.append(crow.data);
        dataDigest = dig.finalize();

        if (not equalDigests(digest, dataDigest)) {
            ThrowMsg(Exception::DecryptDBRowError,
              "Decrypted db row data digest mismatch.");
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

void CryptoLogic::encBase64(SafeBuffer &data)
{
    Base64Encoder benc;
    SafeBuffer encdata;

    benc.append(data);
    benc.finalize();
    encdata = benc.get();

    if (encdata.size() == 0) {
        ThrowMsg(Exception::Base64EncoderError, "Base64Encoder returned empty data.");
    }

    data = std::move(encdata);
}

void CryptoLogic::decBase64(SafeBuffer &data)
{
    Base64Decoder bdec;
    SafeBuffer decdata;

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

bool CryptoLogic::equalDigests(SafeBuffer &dig1, SafeBuffer &dig2)
{
    unsigned int dlen = Digest().length();

    if ((dig1.size() != dlen) || (dig2.size() != dlen))
        return false;
    return (dig1 == dig2);
}

} // namespace CKM

