/* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 * @file        client-manager-impl.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Manager implementation.
 */
#include <openssl/evp.h>

#include <dpl/serialization.h>
#include <dpl/log/log.h>

#include <crypto-init.h>
#include <client-manager-impl.h>
#include <client-common.h>
#include <message-buffer.h>
#include <protocols.h>
#include <key-impl.h>
#include <key-aes-impl.h>
#include <certificate-impl.h>

namespace CKM {

namespace {
template <class T>
int getCertChain(
    ServiceConnection & serviceConnection,
    LogicCommand command,
    int counter,
    const CertificateShPtr &certificate,
    const T &untrustedVector,
    const T &trustedVector,
    bool useTrustedSystemCertificates,
    CertificateShPtrVector &certificateChainVector)
{
    return try_catch([&] {

        MessageBuffer recv;
        auto send = MessageBuffer::Serialize(static_cast<int>(command),
                                             counter,
                                             certificate->getDER(),
                                             untrustedVector,
                                             trustedVector,
                                             useTrustedSystemCertificates);

        int retCode = serviceConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int retCommand;
        int retCounter;
        RawBufferVector rawBufferVector;
        recv.Deserialize(retCommand, retCounter, retCode, rawBufferVector);

        if ((counter != retCounter) || (static_cast<int>(command) != retCommand)) {
            return CKM_API_ERROR_UNKNOWN;
        }

        if (retCode != CKM_API_SUCCESS) {
            return retCode;
        }

        for (auto &e: rawBufferVector) {
            CertificateShPtr cert(new CertificateImpl(e, DataFormat::FORM_DER));
            if (cert->empty())
                return CKM_API_ERROR_BAD_RESPONSE;
            certificateChainVector.push_back(cert);
        }

        return retCode;
    });
}

} // namespace anonymous

Manager::Impl::Impl()
  : m_counter(0),
    m_storageConnection(SERVICE_SOCKET_CKM_STORAGE),
    m_ocspConnection(SERVICE_SOCKET_OCSP),
    m_encryptionConnection(SERVICE_SOCKET_ENCRYPTION)
{
    initOpenSslOnce();
}


int Manager::Impl::saveBinaryData(
    const Alias &alias,
    DataType dataType,
    const RawBuffer &rawData,
    const Policy &policy)
{
    int my_counter = ++m_counter;

    return try_catch([&] {
        if (alias.empty() || rawData.empty())
            return CKM_API_ERROR_INPUT_PARAM;

        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SAVE),
                                             my_counter,
                                             static_cast<int>(dataType),
                                             helper.getName(),
                                             helper.getLabel(),
                                             rawData,
                                             PolicySerializable(policy));

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        int opType;
        recv.Deserialize(command, counter, retCode, opType);

        if (counter != my_counter)
            return CKM_API_ERROR_UNKNOWN;

        return retCode;
    });
}

int Manager::Impl::saveKey(const Alias &alias, const KeyShPtr &key, const Policy &policy) {
    if (key.get() == NULL)
        return CKM_API_ERROR_INPUT_PARAM;
    Try {
        return saveBinaryData(alias, DataType(key->getType()), key->getDER(), policy);
    } Catch (DataType::Exception::Base) {
        LogError("Error in key conversion. Could not convert KeyType::NONE to DBDataType!");
    }
    return CKM_API_ERROR_INPUT_PARAM;
}

int Manager::Impl::saveCertificate(
    const Alias &alias,
    const CertificateShPtr &cert,
    const Policy &policy)
{
    if (cert.get() == NULL)
        return CKM_API_ERROR_INPUT_PARAM;
    return saveBinaryData(alias, DataType::CERTIFICATE, cert->getDER(), policy);
}

int Manager::Impl::saveData(const Alias &alias, const RawBuffer &rawData, const Policy &policy) {
    if (!policy.extractable)
        return CKM_API_ERROR_INPUT_PARAM;
    return saveBinaryData(alias, DataType::BINARY_DATA, rawData, policy);
}


int Manager::Impl::savePKCS12(
    const Alias & alias,
    const PKCS12ShPtr &pkcs,
    const Policy &keyPolicy,
    const Policy &certPolicy)
{
    if (alias.empty() || pkcs.get()==NULL)
        return CKM_API_ERROR_INPUT_PARAM;

    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SAVE_PKCS12),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel(),
                                             PKCS12Serializable(*pkcs.get()),
                                             PolicySerializable(keyPolicy),
                                             PolicySerializable(certPolicy));

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);

        if (counter != my_counter)
            return CKM_API_ERROR_UNKNOWN;

        return retCode;
    });
}

int Manager::Impl::getPKCS12(const Alias &alias, PKCS12ShPtr &pkcs)
{
    return getPKCS12(alias, Password(), Password(), pkcs);
}

int Manager::Impl::getPKCS12(const Alias &alias, const Password &keyPass, const Password &certPass, PKCS12ShPtr &pkcs)
{
    if (alias.empty())
        return CKM_API_ERROR_INPUT_PARAM;

    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_PKCS12),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel(),
                                             keyPass,
                                             certPass);

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        PKCS12Serializable gotPkcs;
        recv.Deserialize(command, counter, retCode, gotPkcs);

        if (counter != my_counter)
            return CKM_API_ERROR_UNKNOWN;

        pkcs = std::make_shared<PKCS12Impl>(std::move(gotPkcs));

        return retCode;
    });
}


int Manager::Impl::removeAlias(const Alias &alias)
{
    if (alias.empty())
        return CKM_API_ERROR_INPUT_PARAM;

    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::REMOVE),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel());

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);

        if (counter != my_counter)
            return CKM_API_ERROR_UNKNOWN;

        return retCode;
    });
}

int Manager::Impl::getBinaryData(
    const Alias &alias,
    DataType sendDataType,
    const Password &password,
    DataType &recvDataType,
    RawBuffer &rawData)
{
    if (alias.empty())
        return CKM_API_ERROR_INPUT_PARAM;

    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET),
                                             my_counter,
                                             static_cast<int>(sendDataType),
                                             helper.getName(),
                                             helper.getLabel(),
                                             password);

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        int tmpDataType;
        recv.Deserialize(command, counter, retCode, tmpDataType, rawData);
        recvDataType = DataType(tmpDataType);

        if (counter != my_counter)
            return CKM_API_ERROR_UNKNOWN;

        return retCode;
    });
}

int Manager::Impl::getKey(const Alias &alias, const Password &password, KeyShPtr &key) {
    DataType recvDataType;
    RawBuffer rawData;

    int retCode = getBinaryData(
        alias,
        DataType::KEY_RSA_PUBLIC,
        password,
        recvDataType,
        rawData);

    if (retCode != CKM_API_SUCCESS)
        return retCode;

    KeyShPtr keyParsed;
    if(DataType::KEY_AES == recvDataType)
        keyParsed = KeyShPtr(new KeyAESImpl(rawData));
    else
        keyParsed = KeyShPtr(new KeyImpl(rawData));

    if (keyParsed->empty()) {
        LogDebug("Key empty - failed to parse!");
        return CKM_API_ERROR_BAD_RESPONSE;
    }

    key = keyParsed;

    return CKM_API_SUCCESS;
}

int Manager::Impl::getCertificate(const Alias &alias, const Password &password, CertificateShPtr &cert)
{
    DataType recvDataType;
    RawBuffer rawData;

    int retCode = getBinaryData(
        alias,
        DataType::CERTIFICATE,
        password,
        recvDataType,
        rawData);

    if (retCode != CKM_API_SUCCESS)
        return retCode;

    if (recvDataType != DataType::CERTIFICATE)
        return CKM_API_ERROR_BAD_RESPONSE;

    CertificateShPtr certParsed(new CertificateImpl(rawData, DataFormat::FORM_DER));

    if (certParsed->empty())
        return CKM_API_ERROR_BAD_RESPONSE;

    cert = certParsed;

    return CKM_API_SUCCESS;
}

int Manager::Impl::getData(const Alias &alias, const Password &password, RawBuffer &rawData)
{
    DataType recvDataType = DataType::BINARY_DATA;

    int retCode = getBinaryData(
        alias,
        DataType::BINARY_DATA,
        password,
        recvDataType,
        rawData);

    if (retCode != CKM_API_SUCCESS)
        return retCode;

    if (recvDataType != DataType::BINARY_DATA)
        return CKM_API_ERROR_BAD_RESPONSE;

    return CKM_API_SUCCESS;
}

int Manager::Impl::getBinaryDataAliasVector(DataType dataType, AliasVector &aliasVector)
{
    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_LIST),
                                             my_counter,
                                             static_cast<int>(dataType));

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        int tmpDataType;
        LabelNameVector labelNameVector;
        recv.Deserialize(command, counter, retCode, tmpDataType, labelNameVector);
        if ((command != static_cast<int>(LogicCommand::GET_LIST)) || (counter != my_counter)) {
            return CKM_API_ERROR_UNKNOWN;
        }

        for(const auto &it : labelNameVector)
            aliasVector.push_back( AliasSupport::merge(it.first, it.second) );

        return retCode;
    });
}

int Manager::Impl::getKeyAliasVector(AliasVector &aliasVector) {
    // in fact datatype has no meaning here - if not certificate or binary data
    // then manager decides to list all between DB_KEY_FIRST and DB_KEY_LAST
    return getBinaryDataAliasVector(DataType::DB_KEY_LAST, aliasVector);
}

int Manager::Impl::getCertificateAliasVector(AliasVector &aliasVector) {
    return getBinaryDataAliasVector(DataType::CERTIFICATE, aliasVector);
}

int Manager::Impl::getDataAliasVector(AliasVector &aliasVector) {
    return getBinaryDataAliasVector(DataType::BINARY_DATA, aliasVector);
}

int Manager::Impl::createKeyPairRSA(
    const int size,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    return this->createKeyPair(CKM::KeyType::KEY_RSA_PUBLIC, size, privateKeyAlias, publicKeyAlias, policyPrivateKey, policyPublicKey);
}

int Manager::Impl::createKeyPairDSA(
    const int size,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    return this->createKeyPair(CKM::KeyType::KEY_DSA_PUBLIC, size, privateKeyAlias, publicKeyAlias, policyPrivateKey, policyPublicKey);
}

int Manager::Impl::createKeyPairECDSA(
    ElipticCurve type,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    return this->createKeyPair(CKM::KeyType::KEY_ECDSA_PUBLIC, static_cast<int>(type), privateKeyAlias, publicKeyAlias, policyPrivateKey, policyPublicKey);
}

int Manager::Impl::createKeyAES(
    const int size,
    const Alias &keyAlias,
    const Policy &policyKey)
{
    // proceed with sending request
    int my_counter = ++m_counter;

    return try_catch([&] {

        MessageBuffer recv;
        AliasSupport aliasHelper(keyAlias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::CREATE_KEY_AES),
                                             my_counter,
                                             static_cast<int>(size),
                                             PolicySerializable(policyKey),
                                             aliasHelper.getName(),
                                             aliasHelper.getLabel());

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);
        if (counter != my_counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}


int Manager::Impl::createKeyPair(
    const KeyType key_type,
    const int     additional_param,
    const Alias  &privateKeyAlias,
    const Alias  &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    // input type check
    CryptoAlgorithm keyGenAlgorithm;
    switch(key_type)
    {
        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_RSA_PRIVATE:
            keyGenAlgorithm.setParam(ParamName::ALGO_TYPE, AlgoType::RSA_GEN);
            keyGenAlgorithm.setParam(ParamName::GEN_KEY_LEN, additional_param);
            break;

        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_DSA_PRIVATE:
            keyGenAlgorithm.setParam(ParamName::ALGO_TYPE, AlgoType::DSA_GEN);
            keyGenAlgorithm.setParam(ParamName::GEN_KEY_LEN, additional_param);
            break;

        case KeyType::KEY_ECDSA_PUBLIC:
        case KeyType::KEY_ECDSA_PRIVATE:
            keyGenAlgorithm.setParam(ParamName::ALGO_TYPE, AlgoType::ECDSA_GEN);
            keyGenAlgorithm.setParam(ParamName::GEN_EC, additional_param);
            break;

        default:
            return CKM_API_ERROR_INPUT_PARAM;
    }

    // proceed with sending request
    int my_counter = ++m_counter;

    return try_catch([&] {

        MessageBuffer recv;
        AliasSupport privateHelper(privateKeyAlias);
        AliasSupport publicHelper(publicKeyAlias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::CREATE_KEY_PAIR),
                                             my_counter,
                                             CryptoAlgorithmSerializable(keyGenAlgorithm),
                                             PolicySerializable(policyPrivateKey),
                                             PolicySerializable(policyPublicKey),
                                             privateHelper.getName(),
                                             privateHelper.getLabel(),
                                             publicHelper.getName(),
                                             publicHelper.getLabel());

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);
        if (counter != my_counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::Impl::getCertificateChain(
    const CertificateShPtr &certificate,
    const CertificateShPtrVector &untrustedCertificates,
    const CertificateShPtrVector &trustedCertificates,
    bool useTrustedSystemCertificates,
    CertificateShPtrVector &certificateChainVector)
{
    RawBufferVector untrustedVector;
    RawBufferVector trustedVector;

    if(!certificate || certificate->empty())
        return CKM_API_ERROR_INPUT_PARAM;

    for (auto &e: untrustedCertificates) {
        untrustedVector.push_back(e->getDER());
    }
    for (auto &e: trustedCertificates) {
        trustedVector.push_back(e->getDER());
    }

    return getCertChain(
            m_storageConnection,
            LogicCommand::GET_CHAIN_CERT,
            ++m_counter,
            certificate,
            untrustedVector,
            trustedVector,
            useTrustedSystemCertificates,
            certificateChainVector);
}

int Manager::Impl::getCertificateChain(
    const CertificateShPtr &certificate,
    const AliasVector &untrustedCertificates,
    const AliasVector &trustedCertificates,
    bool useTrustedSystemCertificates,
    CertificateShPtrVector &certificateChainVector)
{
    LabelNameVector untrustedVector;
    LabelNameVector trustedVector;

    if(!certificate || certificate->empty())
        return CKM_API_ERROR_INPUT_PARAM;

    for (auto &e: untrustedCertificates) {
        AliasSupport helper(e);
        untrustedVector.push_back(std::make_pair(helper.getLabel(), helper.getName()));
    }
    for (auto &e: trustedCertificates) {
        AliasSupport helper(e);
        trustedVector.push_back(std::make_pair(helper.getLabel(), helper.getName()));
    }

    return getCertChain(
            m_storageConnection,
            LogicCommand::GET_CHAIN_ALIAS,
            ++m_counter,
            certificate,
            untrustedVector,
            trustedVector,
            useTrustedSystemCertificates,
            certificateChainVector);
}

int Manager::Impl::createSignature(
    const Alias &privateKeyAlias,
    const Password &password,           // password for private_key
    const RawBuffer &message,
    const CryptoAlgorithm &cAlgorithm,
    RawBuffer &signature)
{
    int my_counter = ++m_counter;

    return try_catch([&] {

        MessageBuffer recv;
        AliasSupport helper(privateKeyAlias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::CREATE_SIGNATURE),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel(),
                                             password,
                                             message,
                                             CryptoAlgorithmSerializable(cAlgorithm));

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode, signature);

        if ((command != static_cast<int>(LogicCommand::CREATE_SIGNATURE))
            || (counter != my_counter))
        {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::Impl::verifySignature(
    const Alias &publicKeyOrCertAlias,
    const Password &password,           // password for public_key (optional)
    const RawBuffer &message,
    const RawBuffer &signature,
    const CryptoAlgorithm &cAlg)
{
    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(publicKeyOrCertAlias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::VERIFY_SIGNATURE),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel(),
                                             password,
                                             message,
                                             signature,
                                             CryptoAlgorithmSerializable(cAlg));

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);

        if ((command != static_cast<int>(LogicCommand::VERIFY_SIGNATURE))
            || (counter != my_counter))
        {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::Impl::ocspCheck(const CertificateShPtrVector &certChain, int &ocspStatus)
{
    return try_catch([&] {
        int my_counter = ++m_counter;
        MessageBuffer recv;

        RawBufferVector rawCertChain;
        for (auto &e: certChain) {
            if (!e || e->empty()) {
                LogError("Empty certificate");
                return CKM_API_ERROR_INPUT_PARAM;
            }
            rawCertChain.push_back(e->getDER());
        }

        auto send = MessageBuffer::Serialize(my_counter, rawCertChain);

        int retCode = m_ocspConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int counter;
        recv.Deserialize(counter, retCode, ocspStatus);

        if (my_counter != counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::Impl::setPermission(const Alias &alias,
                               const Label &accessor,
                               PermissionMask permissionMask)
{
    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SET_PERMISSION),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel(),
                                             accessor,
                                             permissionMask);

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);

        if (my_counter != counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::Impl::crypt(EncryptionCommand command,
          const CryptoAlgorithm &algo,
          const Alias &keyAlias,
          const Password &password,
          const RawBuffer& input,
          RawBuffer& output)
{
    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(keyAlias);
        CryptoAlgorithmSerializable cas(algo);
        auto send = MessageBuffer::Serialize(static_cast<int>(command),
                                             my_counter,
                                             cas,
                                             helper.getName(),
                                             helper.getLabel(),
                                             password,
                                             input);

        int retCode = m_encryptionConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode, output);

        if (my_counter != counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::Impl::encrypt(const CryptoAlgorithm &algo,
            const Alias &keyAlias,
            const Password &password,
            const RawBuffer& plain,
            RawBuffer& encrypted)
{
    return crypt(EncryptionCommand::ENCRYPT, algo, keyAlias, password, plain, encrypted);
}

int Manager::Impl::decrypt(const CryptoAlgorithm &algo,
                         const Alias &keyAlias,
                         const Password &password,
                         const RawBuffer& encrypted,
                         RawBuffer& decrypted)
{
    return crypt(EncryptionCommand::DECRYPT, algo, keyAlias, password, encrypted, decrypted);
}

} // namespace CKM
