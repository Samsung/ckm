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

#pragma once

#include <map>
#include <ckm/ckm-type.h>
#include <db-crypto.h>
#include <dpl/exception.h>
#include <aesCrypt.h>

namespace CKM {

class DBCryptoModule {
public:
    class Exception
    {
        public:
            DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
            DECLARE_EXCEPTION_TYPE(Base, InternalError)
            DECLARE_EXCEPTION_TYPE(Base, Base64EncoderError)
            DECLARE_EXCEPTION_TYPE(Base, Base64DecoderError)
            DECLARE_EXCEPTION_TYPE(Base, EncryptDBRowError)
            DECLARE_EXCEPTION_TYPE(Base, DecryptDBRowError)
    };
    DBCryptoModule();
    DBCryptoModule(const DBCryptoModule &second) = delete;
    DBCryptoModule(DBCryptoModule &&second);
    DBCryptoModule& operator=(DBCryptoModule &&second);
    DBCryptoModule& operator=(const DBCryptoModule &second) = delete;

    virtual ~DBCryptoModule(){}

    int decryptRow(const std::string &password, DBRow &row);
    int encryptRow(const std::string &password, DBRow &row);

    bool haveKey(const std::string &smackLabel);
    int pushKey(const std::string &smackLabel,
                const RawBuffer &applicationKey);

private:
	static const int ENCR_BASE64 =   1 << 0;
	static const int ENCR_APPKEY =   1 << 1;
	static const int ENCR_PASSWORD = 1 << 2;
	
	std::map<std::string, RawBuffer> m_keyMap;

    /* TODO: Move it to private/protected after tests (or remove if not needed) */
    CryptoAlgConf cryptAES(RawBuffer &data, const RawBuffer &key,
                           const RawBuffer &iv, std::string password);
    void decryptAES(RawBuffer &data, const RawBuffer &key, const RawBuffer &iv,
                    std::string password);
    void decBase64(RawBuffer &data);
    void encBase64(RawBuffer &data);
    bool equalDigests(RawBuffer &dig1, RawBuffer &dig2);
    std::size_t insertDigest(RawBuffer &data, const int dataSize);
    void generateKeysFromPassword(const std::string &password,
                                  RawBuffer &key, RawBuffer &iv);
    void removeDigest(RawBuffer &data, RawBuffer &digest);
};

} // namespace CKM

