/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        ckmc-control.h
 * @author      Yuseok Jeon(yuseok.jeon@samsung.com)
 * @version     1.0
 * @brief       provides conversion methods to C from C++ for key-manager control functions.
 */

#include <ckm/ckm-type.h>
#include <ckm/ckm-manager.h>
#include <ckmc/ckmc-type.h>
#include <ckmc/ckmc-manager.h>
#include <ckmc/ckmc-error.h>
#include <ckmc-type-converter.h>
#include <iostream>
#include <string.h>

CKM::Password _tostring(const char *str)
{
    if(str == NULL)
        return CKM::Password();
    return CKM::Password(str);
}

CKM::CertificateShPtr _toCkmCertificate(const ckmc_cert_s *cert)
{
    CKM::RawBuffer buffer(cert->raw_cert, cert->raw_cert + cert->cert_size);
    CKM::DataFormat dataFormat = static_cast<CKM::DataFormat>(static_cast<int>(cert->data_format));
    return CKM::Certificate::create(buffer, dataFormat);
}

ckmc_cert_list_s *_toNewCkmCertList(CKM::CertificateShPtrVector &certVector)
{
    int ret;
    ckmc_cert_list_s *start = NULL;
    ckmc_cert_list_s *plist = NULL;
    CKM::CertificateShPtrVector::iterator it;
    for(it = certVector.begin(); it != certVector.end(); it++) {
        CKM::RawBuffer rawBuffer = (*it)->getDER();
        unsigned char *rawCert = static_cast<unsigned char *>(malloc(rawBuffer.size()));
        memcpy(rawCert, rawBuffer.data(), rawBuffer.size());
        ckmc_cert_s *pcert;
        ret = ckmc_cert_new(rawCert, rawBuffer.size(), CKMC_FORM_DER, &pcert);
        free(rawCert);
        if(pcert == NULL) {
            ckmc_cert_list_all_free(start);
            return NULL;
        }
        if(plist == NULL) {
            ret = ckmc_cert_list_new(pcert, &plist);
            start = plist; // save the pointer of the first element
        }else {
            ret = ckmc_cert_list_add(plist, pcert, &plist);
        }
        if(ret != CKMC_ERROR_NONE) {
            ckmc_cert_list_all_free(start);
            return NULL;
        }
    }
    return start;
}

KEY_MANAGER_CAPI
int ckmc_save_key(const char *alias, const ckmc_key_s key, const ckmc_policy_s policy)
{
    CKM::ManagerShPtr mgr = CKM::Manager::create();

    if(alias == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::Alias ckmAlias(alias);

    if(key.raw_key == NULL || key.key_size <= 0) {
            return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::RawBuffer buffer(key.raw_key, key.raw_key + key.key_size);
    CKM::KeyShPtr ckmKey = CKM::Key::create(buffer, _tostring(key.password));

    if(ckmKey.get() == NULL) {
        return CKMC_ERROR_INVALID_FORMAT;
    }

    CKM::Policy storePolicy(_tostring(policy.password), policy.extractable);

    int ret =  mgr->saveKey(ckmAlias, ckmKey, storePolicy);
    return to_ckmc_error(ret);
}


KEY_MANAGER_CAPI
int ckmc_remove_key(const char *alias)
{
    CKM::ManagerShPtr mgr = CKM::Manager::create();

    if(alias == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::Alias ckmAlias(alias);

    int ret =  mgr->removeKey(ckmAlias);
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_get_key(const char *alias, const char *password, ckmc_key_s **key)
{
    int ret;
    CKM::KeyShPtr ckmKey;

    if(alias == NULL || key == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::Alias ckmAlias(alias);

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    if( (ret = mgr->getKey(ckmAlias, _tostring(password), ckmKey)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    unsigned char *rawKey = reinterpret_cast<unsigned char*>(ckmKey->getDER().data());
    ckmc_key_type_e keyType = static_cast<ckmc_key_type_e>(static_cast<int>(ckmKey->getType()));

    ret = ckmc_key_new( rawKey, ckmKey->getDER().size(), keyType, NULL, key);

    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_get_key_alias_list(ckmc_alias_list_s** alias_list)
{
    int ret;

    if (alias_list == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::AliasVector aliasVector;
    CKM::ManagerShPtr mgr = CKM::Manager::create();

    if ((ret = mgr->getKeyAliasVector(aliasVector)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    ckmc_alias_list_s *plist = NULL;

    for (auto it = aliasVector.begin(); it != aliasVector.end(); it++) {
        char *alias = strndup(it->c_str(), it->size());

        if (plist == NULL) { // first
            ret = ckmc_alias_list_new(alias, &plist);
            *alias_list = plist; // save the pointer of the first element
        } else {
            ret = ckmc_alias_list_add(plist, alias, &plist);
        }

        if (ret != CKMC_ERROR_NONE) {
            free(alias);
            ckmc_alias_list_all_free(*alias_list);
            return ret;
        }
    }

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_save_cert(const char *alias, const ckmc_cert_s cert, const ckmc_policy_s policy)
{
    if(alias == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::Alias ckmAlias(alias);

    if(cert.raw_cert == NULL || cert.cert_size <= 0) {
            return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::CertificateShPtr ckmCert = _toCkmCertificate(&cert);
    if(ckmCert.get() == NULL) {
        return CKMC_ERROR_INVALID_FORMAT;
    }

    CKM::Policy storePolicy(_tostring(policy.password), policy.extractable);

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    int ret = mgr->saveCertificate(ckmAlias, ckmCert, storePolicy);

    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_remove_cert(const char *alias)
{
    if(alias == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::Alias ckmAlias(alias);

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    int ret = mgr->removeCertificate(ckmAlias);

    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_get_cert(const char *alias, const char *password, ckmc_cert_s **cert)
{
    CKM::CertificateShPtr ckmCert;
    int ret;

    if(alias == NULL || cert == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::Alias ckmAlias(alias);

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    if( (ret = mgr->getCertificate(ckmAlias, _tostring(password), ckmCert)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    unsigned char *rawCert = reinterpret_cast<unsigned char*>(ckmCert->getDER().data());
    ret = ckmc_cert_new( rawCert, ckmCert->getDER().size(), CKMC_FORM_DER, cert);

    return ret;
}

KEY_MANAGER_CAPI
int ckmc_get_cert_alias_list(ckmc_alias_list_s** alias_list) {
    int ret;

    if (alias_list == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    *alias_list = NULL;

    CKM::AliasVector aliasVector;
    CKM::ManagerShPtr mgr = CKM::Manager::create();
    if ((ret = mgr->getCertificateAliasVector(aliasVector)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    ckmc_alias_list_s *plist = NULL;

    for (auto it = aliasVector.begin(); it != aliasVector.end(); it++) {
        char *alias = strndup(it->c_str(), it->size());

        if (plist == NULL) { // first
            ret  = ckmc_alias_list_new(alias, &plist);
            *alias_list = plist; // save the pointer of the first element
        } else {
            ret = ckmc_alias_list_add(plist, alias, &plist);
        }

        if (ret != CKMC_ERROR_NONE) {
            free(alias);
            ckmc_alias_list_all_free(*alias_list);
            return ret;
        }
    }

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_save_data(const char *alias, ckmc_raw_buffer_s data, const ckmc_policy_s policy)
{
    if(alias == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::Alias ckmAlias(alias);

    if(data.data == NULL || data.size <= 0) {
            return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::RawBuffer buffer(data.data, data.data + data.size);

    CKM::Policy storePolicy(_tostring(policy.password), policy.extractable);

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    int ret = mgr->saveData(ckmAlias, buffer, storePolicy);

    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_remove_data(const char *alias)
{
    if(alias == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::Alias ckmAlias(alias);

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    int ret = mgr->removeData(ckmAlias);
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_get_data(const char *alias, const char *password, ckmc_raw_buffer_s **data)
{
    CKM::RawBuffer ckmBuff;
    int ret;

    if(alias == NULL || data == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::Alias ckmAlias(alias);

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    if( (ret = mgr->getData(ckmAlias, _tostring(password), ckmBuff)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    unsigned char *rawBuff = reinterpret_cast<unsigned char*>(ckmBuff.data());
    ret = ckmc_buffer_new(rawBuff, ckmBuff.size(), data);

    return ret;
}

KEY_MANAGER_CAPI
int ckmc_get_data_alias_list(ckmc_alias_list_s** alias_list){
    int ret;

    if(alias_list == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    *alias_list = NULL;

    CKM::AliasVector aliasVector;
    CKM::ManagerShPtr mgr = CKM::Manager::create();
    if( (ret = mgr->getDataAliasVector(aliasVector)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    ckmc_alias_list_s *plist = NULL;

    for(auto it = aliasVector.begin(); it != aliasVector.end(); it++) {
        char *alias = strndup(it->c_str(), it->size());

        if (plist == NULL) { // first
            ret = ckmc_alias_list_new(alias, &plist);
            *alias_list = plist; // save the pointer of the first element
        } else {
            ret = ckmc_alias_list_add(plist, alias, &plist);
        }

        if (ret != CKMC_ERROR_NONE) {
            free(alias);
            ckmc_alias_list_all_free(*alias_list);
            return ret;
        }
    }

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_create_key_pair_rsa(const size_t size,
                            const char *private_key_alias,
                            const char *public_key_alias,
                            const ckmc_policy_s policy_private_key,
                            const ckmc_policy_s policy_public_key)
{
    int ret;
    CKM::ManagerShPtr mgr = CKM::Manager::create();

    if(private_key_alias == NULL || public_key_alias == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::Alias ckmPrivakeKeyAlias(private_key_alias);
    CKM::Alias ckmPublicKeyAlias(public_key_alias);
    CKM::Policy ckmPrivateKeyPolicy(_tostring(policy_private_key.password), policy_private_key.extractable);
    CKM::Policy ckmPublicKeyPolicy(_tostring(policy_public_key.password), policy_public_key.extractable);

    ret = mgr->createKeyPairRSA(size, ckmPrivakeKeyAlias, ckmPublicKeyAlias, ckmPrivateKeyPolicy, ckmPublicKeyPolicy);
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_create_key_pair_ecdsa(const ckmc_ec_type_e type,
                            const char *private_key_alias,
                            const char *public_key_alias,
                            const ckmc_policy_s policy_private_key,
                            const ckmc_policy_s policy_public_key)
{
    CKM::ManagerShPtr mgr = CKM::Manager::create();

    if(private_key_alias == NULL || public_key_alias == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::ElipticCurve ckmType = static_cast<CKM::ElipticCurve>(static_cast<int>(type));
    CKM::Alias ckmPrivakeKeyAlias(private_key_alias);
    CKM::Alias ckmPublicKeyAlias(public_key_alias);
    CKM::Policy ckmPrivateKeyPolicy(_tostring(policy_private_key.password), policy_private_key.extractable);
    CKM::Policy ckmPublicKeyPolicy(_tostring(policy_public_key.password), policy_public_key.extractable);

    int ret = mgr->createKeyPairECDSA(ckmType, ckmPrivakeKeyAlias, ckmPublicKeyAlias, ckmPrivateKeyPolicy, ckmPublicKeyPolicy);
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_create_signature(const char *private_key_alias,
                            const char *password,
                            const ckmc_raw_buffer_s message,
                            const ckmc_hash_algo_e hash,
                            const ckmc_rsa_padding_algo_e padding,
                            ckmc_raw_buffer_s **signature)
{
    int ret;
    CKM::ManagerShPtr mgr = CKM::Manager::create();
    CKM::RawBuffer ckmSignature;

    if(private_key_alias == NULL || signature == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::Alias ckmPrivakeKeyAlias(private_key_alias);
    CKM::RawBuffer ckmMessage(message.data, message.data + message.size);
    CKM::HashAlgorithm ckmHashAlgo = static_cast<CKM::HashAlgorithm>(static_cast<int>(hash));
    CKM::RSAPaddingAlgorithm ckmPadding = static_cast<CKM::RSAPaddingAlgorithm>(static_cast<int>(padding));

    if( (ret = mgr->createSignature(
            ckmPrivakeKeyAlias,
            _tostring(password),
            ckmMessage,
            ckmHashAlgo,
            ckmPadding,
            ckmSignature)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    unsigned char *rawBuff = reinterpret_cast<unsigned char*>(ckmSignature.data());
    ret = ckmc_buffer_new( rawBuff, ckmSignature.size(), signature);

    return ret;
}

KEY_MANAGER_CAPI
int ckmc_verify_signature(const char *public_key_alias,
                            const char *password,
                            const ckmc_raw_buffer_s message,
                            const ckmc_raw_buffer_s signature,
                            const ckmc_hash_algo_e hash,
                            const ckmc_rsa_padding_algo_e padding)
{
    int ret;
    CKM::ManagerShPtr mgr = CKM::Manager::create();

    if(public_key_alias == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::Alias ckmPublicKeyAlias(public_key_alias);
    CKM::RawBuffer ckmMessage(message.data, message.data + message.size);
    CKM::RawBuffer ckmSignature(signature.data, signature.data + signature.size);
    CKM::HashAlgorithm ckmHashAlgo = static_cast<CKM::HashAlgorithm>(static_cast<int>(hash));
    CKM::RSAPaddingAlgorithm ckmPadding = static_cast<CKM::RSAPaddingAlgorithm>(static_cast<int>(padding));

    if( (ret = mgr->verifySignature(
            ckmPublicKeyAlias,
            _tostring(password),
            ckmMessage,
            ckmSignature,
            ckmHashAlgo,
            ckmPadding)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_get_cert_chain(const ckmc_cert_s *cert, const ckmc_cert_list_s *untrustedcerts, ckmc_cert_list_s **cert_chain_list)
{
    int ret;
    CKM::ManagerShPtr mgr = CKM::Manager::create();
    CKM::CertificateShPtrVector ckmCertChain;

    if(cert == NULL || cert->raw_cert == NULL || cert->cert_size <= 0 || cert_chain_list == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::CertificateShPtr ckmCert = _toCkmCertificate(cert);

    CKM::CertificateShPtrVector ckmUntrustedCerts;
    if(untrustedcerts != NULL) {
        ckmc_cert_list_s *current = NULL;
        ckmc_cert_list_s *next = const_cast<ckmc_cert_list_s *>(untrustedcerts);
        do {
            current = next;
            next = current->next;

            if(current->cert == NULL){
                continue;
            }

            CKM::CertificateShPtr tmpCkmCert = _toCkmCertificate(current->cert);
            ckmUntrustedCerts.push_back(tmpCkmCert);
        }while(next != NULL);
    }

    ret = mgr->getCertificateChain(ckmCert, ckmUntrustedCerts, ckmCertChain);
    if( ret != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    *cert_chain_list = _toNewCkmCertList(ckmCertChain);

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_get_cert_chain_with_alias(const ckmc_cert_s *cert, const ckmc_alias_list_s *untrustedcerts, ckmc_cert_list_s **cert_chain_list)
{
    int ret;
    CKM::ManagerShPtr mgr = CKM::Manager::create();
    CKM::CertificateShPtrVector ckmCertChain;


    if(cert == NULL || cert->raw_cert == NULL || cert->cert_size <= 0 || cert_chain_list == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::CertificateShPtr ckmCert = _toCkmCertificate(cert);
    if(ckmCert.get() == NULL) {
        return CKMC_ERROR_INVALID_FORMAT;
    }

    CKM::AliasVector ckmUntrustedAliases;
    if(untrustedcerts != NULL) {
        ckmc_alias_list_s *current = NULL;
        ckmc_alias_list_s *next = const_cast<ckmc_alias_list_s *>(untrustedcerts);
        do {
            current = next;
            next = current->next;

            if(current->alias == NULL){
                return CKMC_ERROR_INVALID_PARAMETER;
            }
            CKM::Alias ckmAlias(current->alias);
            ckmUntrustedAliases.push_back(ckmAlias);
        }while(next != NULL);
    }

    if( (ret = mgr->getCertificateChain(ckmCert, ckmUntrustedAliases, ckmCertChain)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    *cert_chain_list = _toNewCkmCertList(ckmCertChain);

    return CKMC_ERROR_NONE;
}
