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
 */

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>

#include <dpl/log/log.h>
#include <base64.h>
#include <ckm/ckm-error.h>
#include <digest.h>

#include <DBCryptoModule.h>

namespace CKM {

DBCryptoModule::DBCryptoModule(){}

DBCryptoModule::DBCryptoModule(DBCryptoModule &&second) {
    m_keyMap = std::move(second.m_keyMap);
}

DBCryptoModule& DBCryptoModule::operator=(DBCryptoModule &&second) {
    if (this == &second)
        return *this;
    m_keyMap = std::move(second.m_keyMap);
    return *this;
}

bool DBCryptoModule::haveKey(const std::string &smackLabel)
{
    return (m_keyMap.count(smackLabel) > 0);
}

int DBCryptoModule::pushKey(const std::string &smackLabel,
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
    return CKM_API_SUCCESS;
}

std::size_t DBCryptoModule::insertDigest(RawBuffer &data, const int dataSize)
{
    RawBuffer digest;

    try {
        Digest dig;
        dig.append(data, dataSize);
        digest = dig.finalize();
    } catch (Digest::Exception::Base &e) {
        LogError("Failed to calculate digest in insertDigest: " <<
                 e.DumpToString());
        throw;
    }
    data.insert(data.begin(), digest.begin(), digest.end());
    return digest.size();
}

void DBCryptoModule::removeDigest(RawBuffer &data, RawBuffer &digest)
{
    unsigned int dlen = Digest().length();

    if (data.size() < dlen) {
        ThrowMsg(Exception::InternalError,
                 "Cannot remove digest: data size mismatch.");
    }

    digest.assign(data.begin(), data.begin() + dlen);
    data.erase(data.begin(), data.begin() + dlen);
}

int DBCryptoModule::encryptRow(const std::string &password, DBRow &row)
{
    RawBuffer emptyiv;
    RawBuffer emptykey;
    DBRow crow = row;
    RawBuffer appkey;

    crow.algorithmType = DBCMAlgType::NONE;
    if (row.dataSize <= 0) {
        ThrowMsg(Exception::EncryptDBRowError, "Invalid dataSize.");
    }
    if (!haveKey(row.smackLabel)) {
        ThrowMsg(Exception::EncryptDBRowError, "Missing application key for " <<
                 row.smackLabel << " label.");
    }
    appkey = m_keyMap[row.smackLabel];
    crow.encryptionScheme = 0;

    try {
        insertDigest(crow.data, crow.dataSize);
        cryptAES(crow.data, appkey, emptyiv, "");
        crow.encryptionScheme |= ENCR_APPKEY;
        if (!password.empty()) {
            crow.iv = cryptAES(crow.data, emptykey, emptyiv, password).getIV();
            crow.encryptionScheme |= ENCR_PASSWORD;
        }
        encBase64(crow.data);
        crow.encryptionScheme |= ENCR_BASE64;
        encBase64(crow.iv);
    } catch (Exception::Base &e) {
        LogError("Failed to encrypt db row: " << e.DumpToString());
        throw;
    } catch (AesCrypt::Exception::Base &e) {
        LogError("Failed to encrypt db row: " << e.DumpToString());
        throw;
    }
    crow.algorithmType = DBCMAlgType::AES_CBC_256;
    row = crow;

    return CKM_API_SUCCESS;
}

int DBCryptoModule::decryptRow(const std::string &password, DBRow &row)
{
    DBRow crow = row;
    RawBuffer appkey;
    RawBuffer emptykey;
    RawBuffer dropiv;
    RawBuffer emptyiv;
    RawBuffer digest, dataDigest;

    if (row.dataSize <= 0) {
        ThrowMsg(Exception::DecryptDBRowError, "Invalid dataSize.");
    }
    if (row.algorithmType != DBCMAlgType::AES_CBC_256) {
        ThrowMsg(Exception::DecryptDBRowError, "Invalid algorithm type.");
    }
    if (row.encryptionScheme & ENCR_PASSWORD)
        if (password.empty()) {
            ThrowMsg(Exception::DecryptDBRowError,
                     "DB row is password protected, but given password is "
                     "empty.");
        }
    if (!haveKey(row.smackLabel)) {
        ThrowMsg(Exception::DecryptDBRowError, "Missing application key for " <<
                 row.smackLabel << " label.");
    }
    appkey = m_keyMap[row.smackLabel];

    try {
        decBase64(crow.iv);
        if (crow.encryptionScheme & ENCR_BASE64) {
            decBase64(crow.data);
        }
        if (crow.encryptionScheme & ENCR_PASSWORD) {
            decryptAES(crow.data, emptykey, crow.iv, password);
        }
        if (crow.encryptionScheme & ENCR_APPKEY) {
            decryptAES(crow.data, appkey, emptyiv, "");
        }
        removeDigest(crow.data, digest);
        if (static_cast<std::size_t>(crow.dataSize) != crow.data.size()) {
            ThrowMsg(Exception::DecryptDBRowError,
                     "Decrypted db row data size mismatch.");
        }
        Digest dig;
        dig.append(crow.data);
        dataDigest = dig.finalize();
    } catch (Exception::Base &e) {
        LogError("Failed to decrypt db row: " << e.DumpToString());
        throw;
    } catch (AesCrypt::Exception::Base &e) {
        LogError("Failed to decrypt db row: " << e.DumpToString());
        throw;
    } catch (Digest::Exception::Base &e) {
        LogError("Failed to decrypt db row: " << e.DumpToString());
        throw;
    }
    if (not equalDigests(digest, dataDigest)) {
        ThrowMsg(Exception::DecryptDBRowError,
                 "Decrypted db row data digest mismatch.");
    }
    row = crow;

    return CKM_API_SUCCESS;
}

CryptoAlgConf DBCryptoModule::cryptAES(RawBuffer &data,
                                       const RawBuffer &key,
                                       const RawBuffer &iv,
                                       std::string password)
{
    try {
        AesEncrypt enc(password);

        if (password.empty()) {
            enc.conf.setKey(key);
            enc.conf.setIV(iv);
        }
        enc.append(data);
        data = enc.finalize();
        return enc.conf;
    } catch (CryptoAlgConf::Exception::Base &e) {
        LogError("Failed to configure AES encryption: " << e.DumpToString());
        throw;
    } catch (AesCrypt::Exception::Base &e) {
        LogError("AES encryption failed: " << e.DumpToString());
        throw;
    }
}

void DBCryptoModule::decryptAES(RawBuffer &data, const RawBuffer &key,
                                const RawBuffer &iv, std::string password)
{
    try {
        AesDecrypt dec(password);

        if (password.empty()) {
            dec.conf.setKey(key);
        }
        dec.conf.setIV(iv);
        dec.append(data);
        data = dec.finalize();
    } catch (CryptoAlgConf::Exception::Base &e) {
        LogError("Failed to configure AES decryption: " << e.DumpToString());
        throw;
    } catch (AesCrypt::Exception::Base &e) {
        LogError("AES Decryption failed: " << e.DumpToString());
        throw;
    }
}

void DBCryptoModule::encBase64(RawBuffer &data)
{
    Base64Encoder benc;
    RawBuffer encdata;

    try {
        benc.append(data);
        benc.finalize();
        encdata = benc.get();
    } catch (Base64Encoder::Exception::Base &e) {
        LogError("Failed to encode data in Base64Encoder: " <<
                 e.DumpToString());
        throw;
    }

    if (encdata.size() == 0) {
        ThrowMsg(Exception::Base64EncoderError, "Base64Encoder returned empty data.");
    }

    data = std::move(encdata);
}

void DBCryptoModule::decBase64(RawBuffer &data)
{
    Base64Decoder bdec;
    RawBuffer decdata;

    try {
        bdec.reset();
        bdec.append(data);
        if (not bdec.finalize()) {
            ThrowMsg(Exception::Base64DecoderError,
                     "Failed in Base64Decoder.finalize.");
        }

        decdata = bdec.get();
    } catch (Base64Decoder::Exception::Base &e) {
        LogError("Failed to decode data in Base64Decoder: " <<
                 e.DumpToString());
        throw;
    }
    if (decdata.size() == 0) {
        ThrowMsg(Exception::Base64DecoderError, "Base64Decoder returned empty data.");
    }

    data = std::move(decdata);
}

bool DBCryptoModule::equalDigests(RawBuffer &dig1, RawBuffer &dig2)
{
    unsigned int dlen = Digest().length();

    if ((dig1.size() != dlen) || (dig2.size() != dlen))
        return false;
    return (dig1 == dig2);
}

} // namespace CKM

