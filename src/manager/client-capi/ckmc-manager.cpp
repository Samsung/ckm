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
#include <client-common.h>
#include <iostream>
#include <string.h>

namespace
{
const CKM::CertificateShPtrVector EMPTY_CERT_VECTOR;
const CKM::AliasVector EMPTY_ALIAS_VECTOR;

CKM::Password _tostring(const char *str)
{
    if(str == NULL)
        return CKM::Password();
    return CKM::Password(str);
}

CKM::KeyShPtr _toCkmKey(const ckmc_key_s *key)
{
    if(key)
    {
        CKM::RawBuffer buffer(key->raw_key, key->raw_key + key->key_size);
        return CKM::Key::create(buffer, _tostring(key->password));
    }
    return CKM::KeyShPtr();
}

CKM::CertificateShPtr _toCkmCertificate(const ckmc_cert_s *cert)
{
    if(cert)
    {
        CKM::RawBuffer buffer(cert->raw_cert, cert->raw_cert + cert->cert_size);
        CKM::DataFormat dataFormat = static_cast<CKM::DataFormat>(static_cast<int>(cert->data_format));
        return CKM::Certificate::create(buffer, dataFormat);
    }
    return CKM::CertificateShPtr();
}

CKM::CertificateShPtrVector _toCkmCertificateVector(const ckmc_cert_list_s *list)
{
    CKM::CertificateShPtrVector certs;
    ckmc_cert_list_s *current = const_cast<ckmc_cert_list_s *>(list);
    while (current != NULL)
    {
        if (current->cert != NULL)
            certs.push_back(_toCkmCertificate(current->cert));
        current = current->next;
    }
    return certs;
}

CKM::AliasVector _toCkmAliasVector(const ckmc_alias_list_s *list)
{
    CKM::AliasVector aliases;
    ckmc_alias_list_s *current = const_cast<ckmc_alias_list_s *>(list);
    while (current != NULL)
    {
        if (current->alias != NULL)
            aliases.push_back(CKM::Alias(current->alias));
        current = current->next;
    }
    return aliases;
}

ckmc_cert_list_s *_toNewCkmCertList(const CKM::CertificateShPtrVector &certVector)
{
    int ret;
    ckmc_cert_list_s *start = NULL;
    ckmc_cert_list_s *plist = NULL;
    CKM::CertificateShPtrVector::const_iterator it;
    for(it = certVector.begin(); it != certVector.end(); it++) {
        CKM::RawBuffer rawBuffer = (*it)->getDER();
        ckmc_cert_s *pcert = NULL;
        ret = ckmc_cert_new(rawBuffer.data(), rawBuffer.size(), CKMC_FORM_DER, &pcert);
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
    return ckmc_remove_alias(alias);
}

KEY_MANAGER_CAPI
int ckmc_get_key(const char *alias, const char *password, ckmc_key_s **key)
{
    int ret;
    CKM::KeyShPtr ckmKey;

    if(alias == NULL || key == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    if( (ret = mgr->getKey(alias, _tostring(password), ckmKey)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    CKM::RawBuffer buffer = ckmKey->getDER();
    ckmc_key_type_e keyType = static_cast<ckmc_key_type_e>(static_cast<int>(ckmKey->getType()));

    ret = ckmc_key_new( buffer.data(), buffer.size(), keyType, NULL, key);

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

    for (const auto it : aliasVector) {
        char *alias = strndup(it.c_str(), it.size());

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

    if(plist == NULL) { // if the alias_list size is zero
        return CKMC_ERROR_DB_ALIAS_UNKNOWN;
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
    return ckmc_remove_alias(alias);
}

KEY_MANAGER_CAPI
int ckmc_get_cert(const char *alias, const char *password, ckmc_cert_s **cert)
{
    CKM::CertificateShPtr ckmCert;
    int ret;

    if(alias == NULL || cert == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    if( (ret = mgr->getCertificate(alias, _tostring(password), ckmCert)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    CKM::RawBuffer buffer = ckmCert->getDER();
    ret = ckmc_cert_new( buffer.data(), buffer.size(), CKMC_FORM_DER, cert);

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

    for (const auto it : aliasVector) {
        char *alias = strndup(it.c_str(), it.size());

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

    if(plist == NULL) { // if the alias_list size is zero
        return CKMC_ERROR_DB_ALIAS_UNKNOWN;
    }

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_save_pkcs12(const char *alias, const ckmc_pkcs12_s *ppkcs, const ckmc_policy_s key_policy, const ckmc_policy_s cert_policy)
{
    CKM::KeyShPtr private_key;
    CKM::CertificateShPtr cert;
    CKM::CertificateShPtrVector ca_cert_list;

    if(alias==NULL || ppkcs==NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }
    CKM::Alias ckmAlias(alias);
    private_key = _toCkmKey(ppkcs->priv_key);
    cert = _toCkmCertificate(ppkcs->cert);
    ca_cert_list = _toCkmCertificateVector(ppkcs->ca_chain);

    CKM::Policy keyPolicy(_tostring(key_policy.password), key_policy.extractable);
    CKM::Policy certPolicy(_tostring(cert_policy.password), cert_policy.extractable);

    CKM::PKCS12ShPtr pkcs12(new CKM::PKCS12Impl(private_key, cert, ca_cert_list));

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    int ret = mgr->savePKCS12(ckmAlias, pkcs12, keyPolicy, certPolicy);

    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_remove_pkcs12(const char *alias)
{
    return ckmc_remove_alias(alias);
}

KEY_MANAGER_CAPI
int ckmc_get_pkcs12(const char *alias, const char *key_password, const char *cert_password, ckmc_pkcs12_s **pkcs12)
{
    int ret;
    CKM::PKCS12ShPtr pkcs;
    CKM::Password keyPass, certPass;
    ckmc_key_s *private_key = NULL;
    ckmc_cert_s *cert = NULL;
    ckmc_cert_list_s *ca_cert_list = 0;

    if(!alias || !pkcs12) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    if (key_password)
        keyPass = key_password;

    if (cert_password)
        certPass = cert_password;

    auto mgr = CKM::Manager::create();

    if((ret = mgr->getPKCS12(alias, keyPass, certPass, pkcs)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    if(!pkcs)
        return CKMC_ERROR_BAD_RESPONSE;

    auto pkcsKey = pkcs->getKey();
    if(pkcsKey)
    {
        CKM::RawBuffer buffer = pkcsKey->getDER();
        ckmc_key_type_e keyType = static_cast<ckmc_key_type_e>(pkcsKey->getType());
        ret = ckmc_key_new(buffer.data(), buffer.size(), keyType, NULL, &private_key);
        if(ret != CKMC_ERROR_NONE)
            return ret;
    }

    auto pkcsCert = pkcs->getCertificate();
    if(pkcsCert)
    {
        CKM::RawBuffer buffer = pkcsCert->getDER();
        ret = ckmc_cert_new(buffer.data(), buffer.size(), CKMC_FORM_DER, &cert);
        if(ret != CKMC_ERROR_NONE) {
            ckmc_key_free(private_key);
            return ret;
        }
    }

    ca_cert_list = _toNewCkmCertList(pkcs->getCaCertificateShPtrVector());

    ret = ckmc_pkcs12_new(private_key, cert, ca_cert_list, pkcs12);
    if(ret != CKMC_ERROR_NONE)
    {
        ckmc_key_free(private_key);
        ckmc_cert_free(cert);
        ckmc_cert_list_free(ca_cert_list);
    }
    return ret;
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
    return ckmc_remove_alias(alias);
}

KEY_MANAGER_CAPI
int ckmc_get_data(const char *alias, const char *password, ckmc_raw_buffer_s **data)
{
    CKM::RawBuffer ckmBuff;
    int ret;

    if(alias == NULL || data == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    if( (ret = mgr->getData(alias, _tostring(password), ckmBuff)) != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    ret = ckmc_buffer_new(ckmBuff.data(), ckmBuff.size(), data);

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

    for (const auto it : aliasVector) {
        char *alias = strndup(it.c_str(), it.size());

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

    if(plist == NULL) { // if the alias_list size is zero
        return CKMC_ERROR_DB_ALIAS_UNKNOWN;
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

    ret = mgr->createKeyPairRSA(static_cast<int>(size), ckmPrivakeKeyAlias, ckmPublicKeyAlias, ckmPrivateKeyPolicy, ckmPublicKeyPolicy);
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_create_key_pair_dsa(const size_t size,
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

    ret = mgr->createKeyPairDSA(static_cast<int>(size), ckmPrivakeKeyAlias, ckmPublicKeyAlias, ckmPrivateKeyPolicy, ckmPublicKeyPolicy);
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

    ret = ckmc_buffer_new( ckmSignature.data(), ckmSignature.size(), signature);

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

    CKM::CertificateShPtrVector ckmUntrustedCerts = _toCkmCertificateVector(untrustedcerts);

    ret = mgr->getCertificateChain(ckmCert, ckmUntrustedCerts, EMPTY_CERT_VECTOR, true, ckmCertChain);
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

    CKM::AliasVector ckmUntrustedAliases = _toCkmAliasVector(untrustedcerts);

    ret = mgr->getCertificateChain(ckmCert, ckmUntrustedAliases, EMPTY_ALIAS_VECTOR, true, ckmCertChain);
    if( ret != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    *cert_chain_list = _toNewCkmCertList(ckmCertChain);

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_get_cert_chain_with_trustedcert(const ckmc_cert_s* cert,
                                         const ckmc_cert_list_s* untrustedcerts,
                                         const ckmc_cert_list_s* trustedcerts,
                                         const bool sys_certs,
                                         ckmc_cert_list_s** ppcert_chain_list)
{
    int ret;
    CKM::ManagerShPtr mgr = CKM::Manager::create();
    CKM::CertificateShPtrVector ckm_cert_chain;

    if(cert == NULL || cert->raw_cert == NULL || cert->cert_size <= 0 || ppcert_chain_list == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::CertificateShPtr ckm_cert = _toCkmCertificate(cert);
    if(ckm_cert.get() == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::CertificateShPtrVector ckm_untrusted = _toCkmCertificateVector(untrustedcerts);
    CKM::CertificateShPtrVector ckm_trusted = _toCkmCertificateVector(trustedcerts);

    ret = mgr->getCertificateChain(ckm_cert, ckm_untrusted, ckm_trusted, sys_certs, ckm_cert_chain);
    if( ret != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    *ppcert_chain_list = _toNewCkmCertList(ckm_cert_chain);

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int  ckmc_get_cert_chain_with_trustedcert_alias(const ckmc_cert_s* cert,
                                                const ckmc_alias_list_s* untrustedcerts,
                                                const ckmc_alias_list_s* trustedcerts,
                                                const bool sys_certs,
                                                ckmc_cert_list_s** ppcert_chain_list)
{
    int ret;
    CKM::ManagerShPtr mgr = CKM::Manager::create();
    CKM::CertificateShPtrVector ckm_cert_chain;

    if(cert == NULL || cert->raw_cert == NULL || cert->cert_size <= 0 || ppcert_chain_list == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::CertificateShPtr ckm_cert = _toCkmCertificate(cert);
    if(ckm_cert.get() == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    CKM::AliasVector ckm_untrusted = _toCkmAliasVector(untrustedcerts);
    CKM::AliasVector ckm_trusted = _toCkmAliasVector(trustedcerts);

    ret = mgr->getCertificateChain(ckm_cert, ckm_untrusted, ckm_trusted, sys_certs, ckm_cert_chain);
    if( ret != CKM_API_SUCCESS) {
        return to_ckmc_error(ret);
    }

    *ppcert_chain_list = _toNewCkmCertList(ckm_cert_chain);

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_ocsp_check(const ckmc_cert_list_s *pcert_chain_list, ckmc_ocsp_status_e *ocsp_status)
{
    if (pcert_chain_list == NULL
        || pcert_chain_list->cert == NULL
        || pcert_chain_list->cert->raw_cert == NULL
        || pcert_chain_list->cert->cert_size <= 0
        || ocsp_status == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    int ret = CKMC_ERROR_UNKNOWN;
    int tmpOcspStatus = -1;
    CKM::ManagerShPtr mgr = CKM::Manager::create();
    CKM::CertificateShPtrVector ckmCertChain = _toCkmCertificateVector(pcert_chain_list);

    ret = mgr->ocspCheck(ckmCertChain, tmpOcspStatus);
    *ocsp_status = to_ckmc_ocsp_status(tmpOcspStatus);
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_allow_access(const char *alias, const char *accessor, ckmc_access_right_e granted)
{
    int ec, permissionMask;
    ec = access_to_permission_mask(granted, permissionMask);
    if(ec != CKMC_ERROR_NONE)
        return ec;

    return ckmc_set_permission(alias, accessor, permissionMask);
}

KEY_MANAGER_CAPI
int ckmc_set_permission(const char *alias, const char *accessor, int permissions)
{
    if (!alias || !accessor)
        return CKMC_ERROR_INVALID_PARAMETER;

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    return to_ckmc_error(mgr->setPermission(alias, accessor, permissions));
}

KEY_MANAGER_CAPI
int ckmc_deny_access(const char *alias, const char *accessor)
{
    if (!alias || !accessor)
        return CKMC_ERROR_INVALID_PARAMETER;

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    return to_ckmc_error(mgr->setPermission(alias, accessor, CKM::Permission::NONE));
}

KEY_MANAGER_CAPI
int ckmc_remove_alias(const char *alias)
{
    if(!alias)
        return CKMC_ERROR_INVALID_PARAMETER;

    CKM::ManagerShPtr mgr = CKM::Manager::create();
    int ret =  mgr->removeAlias(alias);
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_encrypt_data(const ckmc_param_list_s */*params*/,
                      const char */*key_alias*/,
                      const char */*password*/,
                      const ckmc_raw_buffer_s /*decrypted*/,
                      ckmc_raw_buffer_s **/*ppencrypted*/)
{
    // TODO implement it
    return CKMC_ERROR_UNKNOWN;
}

KEY_MANAGER_CAPI
int ckmc_decrypt_data(const ckmc_param_list_s */*params*/,
                      const char */*key_alias*/,
                      const char */*password*/,
                      const ckmc_raw_buffer_s /* encrypted*/,
                      ckmc_raw_buffer_s **/*ppdecrypted*/)
{
    // TODO implement it
    return CKMC_ERROR_UNKNOWN;
}
