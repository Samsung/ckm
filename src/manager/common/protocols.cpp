/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 * @file        protocols.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       List of all protocols supported by Central Key Manager.
 */

#include <protocols.h>

#include <dpl/serialization.h>

namespace CKM {

char const * const SERVICE_SOCKET_ECHO = "/tmp/.central-key-manager-echo.sock";
char const * const SERVICE_SOCKET_CKM_CONTROL = "/tmp/.central-key-manager-api-control.sock";
char const * const SERVICE_SOCKET_CKM_STORAGE = "/tmp/.central-key-manager-api-storage.sock";
char const * const SERVICE_SOCKET_OCSP = "/tmp/.central-key-manager-api-ocsp.sock";
char const * const LABEL_NAME_SEPARATOR = " ";


PKCS12Serializable::PKCS12Serializable() {}
PKCS12Serializable::PKCS12Serializable(const PKCS12 &pkcs)
    : PKCS12Impl(pkcs)
{}

PKCS12Serializable::PKCS12Serializable(IStream &stream)
{
    // key
    size_t numKeys;
    Deserialization::Deserialize(stream, numKeys);
    if(numKeys > 0) {
        int keyType;
        RawBuffer keyData;
        Deserialization::Deserialize(stream, keyType);
        Deserialization::Deserialize(stream, keyData);
        m_pkey = CKM::Key::create(keyData);
    }

    // cert
    size_t numCerts;
    Deserialization::Deserialize(stream, numCerts);
    if(numCerts > 0) {
        RawBuffer certData;
        Deserialization::Deserialize(stream, certData);
        m_cert = CKM::Certificate::create(certData, DataFormat::FORM_DER);
    }

    // CA chain
    size_t num_CA;
    Deserialization::Deserialize(stream, num_CA);
    for(size_t i=0; i<num_CA; i++)
    {
        RawBuffer CAcertData;
        Deserialization::Deserialize(stream, CAcertData);
        m_ca.push_back(CKM::Certificate::create(CAcertData, DataFormat::FORM_DER));
    }
}
PKCS12Serializable::PKCS12Serializable(const KeyShPtr &privKey, const CertificateShPtr &cert, const CertificateShPtrVector &chainCerts)
{
    m_pkey = privKey;
    m_cert = cert;
    m_ca = chainCerts;
}

void PKCS12Serializable::Serialize(IStream &stream) const
{
    // key
    Key *keyPtr = getKey().get();
    bool isAnyKeyPresent = (getKey().get()!=NULL);

    // logics if PKCS is correct or not is on the service side.
    // sending number of keys and certificates to allow proper parsing on the service side.
    // (what if no key or cert present? attempt to deserialize a not present key/cert would
    // throw an error and close the connection).
    Serialization::Serialize(stream, static_cast<size_t>(isAnyKeyPresent?1:0));
    if(keyPtr) {
        Serialization::Serialize(stream, DBDataType(keyPtr->getType()));
        Serialization::Serialize(stream, keyPtr->getDER());
    }

    bool isAnyCertPresent = (getCertificate().get()!=NULL);
    Serialization::Serialize(stream, static_cast<size_t>(isAnyCertPresent?1:0));
    if(isAnyCertPresent) {
        Serialization::Serialize(stream, getCertificate().get()->getDER());
    }

    // CA chain
    Serialization::Serialize(stream, getCaCertificateShPtrVector().size());
    for(auto it : getCaCertificateShPtrVector())
        Serialization::Serialize(stream, it->getDER());
};

} // namespace CKM

