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
#include <iostream>
#include <string.h>

bool _toBool(ckmc_bool ckmBool)
{
	if(ckmBool == CKMC_TRUE) {
		return true;
	}
	return false;
}

std::string _tostring(const char *str)
{
	if(str == NULL)
		return std::string();
	return std::string(str);
}

CKM::Certificate _toCkmCertificate(const ckmc_cert *cert)
{
	CKM::RawBuffer buffer(cert->raw_cert, cert->raw_cert + cert->cert_size);
	CKM::DataFormat dataFormat = static_cast<CKM::DataFormat>(static_cast<int>(cert->data_format));
	CKM::Certificate ckmCert(buffer, dataFormat);
	return ckmCert;
}

ckmc_cert_list *_toNewCkmCertList(CKM::CertificateVector &certVector)
{
	ckmc_cert_list *start = NULL;
	ckmc_cert_list *plist = NULL;
	CKM::CertificateVector::iterator it;
	for(it = certVector.begin(); it != certVector.end(); it++) {
		CKM::RawBuffer rawBuffer = it->getDER();
		unsigned char *rawCert = (unsigned char *) malloc(rawBuffer.size());
		memcpy(rawCert, rawBuffer.data(), rawBuffer.size());
		ckmc_cert *pcert = ckmc_cert_new( rawCert, rawBuffer.size(), CKMC_FORM_DER);
		if(pcert == NULL) {
			return NULL;
		}
		if(plist == NULL) {
			plist = ckmc_cert_list_new(pcert);
			start = plist; // save the pointer of the first element
		}else {
			plist = ckmc_cert_list_add(plist, pcert);
		}
	}
	return start;
}

KEY_MANAGER_CAPI
int ckmc_save_key(const char *alias, const ckmc_key key, const ckmc_policy policy)
{
	CKM::Manager mgr;

	if(alias == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	if(key.raw_key == NULL || key.key_size <= 0) {
			return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::RawBuffer buffer(key.raw_key, key.raw_key + key.key_size);
	CKM::Key ckmKey(buffer, _tostring(key.password));

	if(ckmKey.getDER().size() <= 0) {
		return CKMC_API_ERROR_INVALID_FORMAT;
	}

	CKM::Policy storePolicy(_tostring(policy.password), _toBool(policy.extractable), _toBool(policy.restricted));

	return mgr.saveKey(ckmAlias, ckmKey, storePolicy);
}


KEY_MANAGER_CAPI
int ckmc_remove_key(const char *alias)
{
	CKM::Manager mgr;

	if(alias == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	return mgr.removeKey(ckmAlias);
}

KEY_MANAGER_CAPI
int ckmc_get_key(const char *alias, const char *password, ckmc_key **key)
{
	int ret;
	CKM::Key ckmKey;

	if(alias == NULL || key == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	CKM::Manager mgr;
	if( (ret = mgr.getKey(ckmAlias, _tostring(password), ckmKey)) != CKMC_API_SUCCESS) {
		return ret;
	}

	unsigned char *rawKey = reinterpret_cast<unsigned char*>(ckmKey.getDER().data());
	ckmc_key_type keyType = static_cast<ckmc_key_type>(static_cast<int>(ckmKey.getType()));
	*key = ckmc_key_new( rawKey, ckmKey.getDER().size(), keyType, NULL);
	if(*key == NULL) {
		return CKMC_API_ERROR_OUT_OF_MEMORY;
	}else {
		return CKMC_API_SUCCESS;
	}
}

KEY_MANAGER_CAPI
int ckmc_get_key_alias_list(ckmc_alias_list** alias_list)
{
	int ret;
	CKM::Key ckmKey;

	if(alias_list == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}

	CKM::AliasVector aliasVector;
	CKM::Manager mgr;
	if( (ret = mgr.getKeyAliasVector(aliasVector)) != CKMC_API_SUCCESS) {
		return ret;
	}

	ckmc_alias_list *plist = NULL;
	CKM::AliasVector::iterator it;
	for(it = aliasVector.begin(); it != aliasVector.end(); it++) {
		char *alias = (char *)malloc(it->size() + 1);
		memset(alias, 0, it->size() +1 );
		memcpy(alias, it->c_str(), it->size());
		if(plist == NULL) { // first
			plist = ckmc_alias_list_new(alias);
			*alias_list = plist; // save the pointer of the first element
		}else {
			plist = ckmc_alias_list_add(plist, alias);
		}
	}

	return CKMC_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckmc_save_cert(const char *alias, const ckmc_cert cert, const ckmc_policy policy)
{
	if(alias == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	if(cert.raw_cert == NULL || cert.cert_size <= 0) {
			return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::Certificate ckmCert = _toCkmCertificate(&cert);
	if(ckmCert.getDER().size() <= 0) {
		return CKMC_API_ERROR_INVALID_FORMAT;
	}

	CKM::Policy storePolicy(_tostring(policy.password), _toBool(policy.extractable), _toBool(policy.restricted));

	CKM::Manager mgr;
	return mgr.saveCertificate(ckmAlias, ckmCert, storePolicy);
}

KEY_MANAGER_CAPI
int ckmc_remove_cert(const char *alias)
{
	if(alias == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	CKM::Manager mgr;
	return mgr.removeCertificate(ckmAlias);
}

KEY_MANAGER_CAPI
int ckmc_get_cert(const char *alias, const char *password, ckmc_cert **cert)
{
	CKM::Certificate ckmCert;
	int ret;

	if(alias == NULL || cert == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	CKM::Manager mgr;
	if( (ret = mgr.getCertificate(ckmAlias, _tostring(password), ckmCert)) != CKMC_API_SUCCESS) {
		return ret;
	}

	unsigned char *rawCert = reinterpret_cast<unsigned char*>(ckmCert.getDER().data());
	*cert = ckmc_cert_new( rawCert, ckmCert.getDER().size(), CKMC_FORM_DER);
	if(*cert == NULL) {
		return CKMC_API_ERROR_OUT_OF_MEMORY;
	}else {
		return CKMC_API_SUCCESS;
	}
}

KEY_MANAGER_CAPI
int ckmc_get_cert_alias_list(ckmc_alias_list** alias_list) {
	int ret;
	CKM::Key ckmKey;

	if(alias_list == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}

	CKM::AliasVector aliasVector;
	CKM::Manager mgr;
	if( (ret = mgr.getCertificateAliasVector(aliasVector)) != CKMC_API_SUCCESS) {
		return ret;
	}

	ckmc_alias_list *plist = NULL;
	CKM::AliasVector::iterator it;
	for(it = aliasVector.begin(); it != aliasVector.end(); it++) {
		char *alias = (char *)malloc(it->size() + 1);
		memset(alias, 0, it->size() +1 );
		memcpy(alias, it->c_str(), it->size());
		if(plist == NULL) { // first
			plist = ckmc_alias_list_new(alias);
			*alias_list = plist; // save the pointer of the first element
		}else {
			plist = ckmc_alias_list_add(plist, alias);
		}
	}

	return CKMC_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckmc_save_data(const char *alias, ckmc_raw_buffer data, const ckmc_policy policy)
{
	if(alias == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	if(data.data == NULL || data.size <= 0) {
			return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::RawBuffer buffer(data.data, data.data + data.size);

	CKM::Policy storePolicy(_tostring(policy.password), _toBool(policy.extractable), _toBool(policy.restricted));

	CKM::Manager mgr;
	return mgr.saveData(ckmAlias, buffer, storePolicy);
}

KEY_MANAGER_CAPI
int ckmc_remove_data(const char *alias)
{
	if(alias == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	CKM::Manager mgr;
	return mgr.removeData(ckmAlias);
}

KEY_MANAGER_CAPI
int ckmc_get_data(const char *alias, const char *password, ckmc_raw_buffer **data)
{
	CKM::RawBuffer ckmBuff;
	int ret;

	if(alias == NULL || data == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	CKM::Manager mgr;
	if( (ret = mgr.getData(ckmAlias, _tostring(password), ckmBuff)) != CKMC_API_SUCCESS) {
		return ret;
	}

	unsigned char *rawBuff = reinterpret_cast<unsigned char*>(ckmBuff.data());
	*data = ckmc_buffer_new( rawBuff, ckmBuff.size());
	if(*data == NULL) {
		return CKMC_API_ERROR_OUT_OF_MEMORY;
	}else {
		return CKMC_API_SUCCESS;
	}
}

KEY_MANAGER_CAPI
int ckmc_get_data_alias_list(ckmc_alias_list** alias_list){
	int ret;
	CKM::Key ckmKey;

	if(alias_list == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}

	CKM::AliasVector aliasVector;
	CKM::Manager mgr;
	if( (ret = mgr.getDataAliasVector(aliasVector)) != CKMC_API_SUCCESS) {
		return ret;
	}

	ckmc_alias_list *plist = NULL;
	CKM::AliasVector::iterator it;
	for(it = aliasVector.begin(); it != aliasVector.end(); it++) {
		char *alias = (char *)malloc(it->size() + 1);
		memset(alias, 0, it->size() +1 );
		memcpy(alias, it->c_str(), it->size());
		if(plist == NULL) { // first
			plist = ckmc_alias_list_new(alias);
			*alias_list = plist; // save the pointer of the first element
		}else {
			plist = ckmc_alias_list_add(plist, alias);
		}
	}

	return CKMC_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckmc_create_key_pair_rsa(const size_t size,
							const char *private_key_alias,
							const char *public_key_alias,
							const ckmc_policy policy_private_key,
							const ckmc_policy policy_public_key)
{
	int ret;
	CKM::Manager mgr;

	if(private_key_alias == NULL || public_key_alias == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}

	CKM::Alias ckmPrivakeKeyAlias(private_key_alias);
	CKM::Alias ckmPublicKeyAlias(public_key_alias);
	CKM::Policy ckmPrivateKeyPolicy(_tostring(policy_private_key.password), _toBool(policy_private_key.extractable), _toBool(policy_private_key.restricted));
	CKM::Policy ckmPublicKeyPolicy(_tostring(policy_public_key.password), _toBool(policy_public_key.extractable), _toBool(policy_public_key.restricted));

	if( (ret = mgr.createKeyPairRSA(size, ckmPrivakeKeyAlias, ckmPublicKeyAlias, ckmPrivateKeyPolicy, ckmPublicKeyPolicy))
			!= CKMC_API_SUCCESS) {
		return ret;
	}

	return CKMC_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckmc_create_key_pair_ecdsa(const ckmc_ec_type type,
							const char *private_key_alias,
							const char *public_key_alias,
							const ckmc_policy policy_private_key,
							const ckmc_policy policy_public_key)
{
	int ret;
	CKM::Manager mgr;

	if(private_key_alias == NULL || public_key_alias == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}

	CKM::ElipticCurve ckmType = static_cast<CKM::ElipticCurve>(static_cast<int>(type));
	CKM::Alias ckmPrivakeKeyAlias(private_key_alias);
	CKM::Alias ckmPublicKeyAlias(public_key_alias);
	CKM::Policy ckmPrivateKeyPolicy(_tostring(policy_private_key.password), _toBool(policy_private_key.extractable), _toBool(policy_private_key.restricted));
	CKM::Policy ckmPublicKeyPolicy(_tostring(policy_public_key.password), _toBool(policy_public_key.extractable), _toBool(policy_public_key.restricted));

	if( (ret - mgr.createKeyPairECDSA(ckmType, ckmPrivakeKeyAlias, ckmPublicKeyAlias, ckmPrivateKeyPolicy, ckmPublicKeyPolicy))
			!= CKMC_API_SUCCESS) {
		return ret;
	}

	return CKMC_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckmc_create_signature(const char *private_key_alias,
							const char *password,
							const ckmc_raw_buffer message,
							const ckmc_hash_algo hash,
							const ckmc_rsa_padding_algo padding,
							ckmc_raw_buffer **signature)
{
	int ret;
	CKM::Manager mgr;
	CKM::RawBuffer ckmSignature;

	if(private_key_alias == NULL || signature == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}

	CKM::Alias ckmPrivakeKeyAlias(private_key_alias);
	CKM::RawBuffer ckmMessage(message.data, message.data + message.size);
	CKM::HashAlgorithm ckmHashAlgo = static_cast<CKM::HashAlgorithm>(static_cast<int>(hash));
	CKM::RSAPaddingAlgorithm ckmPadding = static_cast<CKM::RSAPaddingAlgorithm>(static_cast<int>(padding));

	if( (ret = mgr.createSignature(
			ckmPrivakeKeyAlias,
			_tostring(password),
			ckmMessage,
			ckmHashAlgo,
			ckmPadding,
			ckmSignature)) != CKMC_API_SUCCESS) {
		return ret;
	}

	unsigned char *rawBuff = reinterpret_cast<unsigned char*>(ckmSignature.data());
	*signature = ckmc_buffer_new( rawBuff, ckmSignature.size());
	if(*signature == NULL) {
		return CKMC_API_ERROR_OUT_OF_MEMORY;
	}else {
		return CKMC_API_SUCCESS;
	}

	return CKMC_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckmc_verify_signature(const char *public_key_alias,
							const char *password,
							const ckmc_raw_buffer message,
							const ckmc_raw_buffer signature,
							const ckmc_hash_algo hash,
							const ckmc_rsa_padding_algo padding)
{
	int ret;
	CKM::Manager mgr;

	if(public_key_alias == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}

	CKM::Alias ckmPublicKeyAlias(public_key_alias);
	CKM::RawBuffer ckmMessage(message.data, message.data + message.size);
	CKM::RawBuffer ckmSignature(signature.data, signature.data + signature.size);
	CKM::HashAlgorithm ckmHashAlgo = static_cast<CKM::HashAlgorithm>(static_cast<int>(hash));
	CKM::RSAPaddingAlgorithm ckmPadding = static_cast<CKM::RSAPaddingAlgorithm>(static_cast<int>(padding));

	if( (ret = mgr.verifySignature(
			ckmPublicKeyAlias,
			_tostring(password),
			ckmMessage,
			ckmSignature,
			ckmHashAlgo,
			ckmPadding)) != CKMC_API_SUCCESS) {
		return ret;
	}

	return CKMC_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckmc_get_cert_chain(const ckmc_cert *cert, const ckmc_cert_list *untrustedcerts, ckmc_cert_list **cert_chain_list)
{
	int ret;
	CKM::Manager mgr;
	CKM::CertificateVector ckmCertChain;

	if(cert == NULL || cert->raw_cert == NULL || cert->cert_size <= 0 || cert_chain_list == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}

	CKM::Certificate ckmCert = _toCkmCertificate(cert);

	CKM::CertificateVector ckmUntrustedCerts;
	if(untrustedcerts != NULL) {
		ckmc_cert_list *current = NULL;
		ckmc_cert_list *next = const_cast<ckmc_cert_list *>(untrustedcerts);
		do {
			current = next;
			next = current->next;

			if(current->cert == NULL){
				continue;
			}

			CKM::Certificate tmpCkmCert = _toCkmCertificate(current->cert);
			ckmUntrustedCerts.push_back(tmpCkmCert);
		}while(next != NULL);
	}

	ret = mgr.getCertificateChain(ckmCert, ckmUntrustedCerts, ckmCertChain);
	if( ret != CKMC_API_SUCCESS) {
		return ret;
	}

	*cert_chain_list = _toNewCkmCertList(ckmCertChain);

	return CKMC_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckmc_get_cert_chain_with_alias(const ckmc_cert *cert, const ckmc_alias_list *untrustedcerts, ckmc_cert_list **cert_chain_list)
{
	int ret;
	CKM::Manager mgr;
	CKM::CertificateVector ckmCertChain;


	if(cert == NULL || cert->raw_cert == NULL || cert->cert_size <= 0 || cert_chain_list == NULL) {
		return CKMC_API_ERROR_INPUT_PARAM;
	}
	CKM::RawBuffer buffer(cert->raw_cert, cert->raw_cert + cert->cert_size);
	CKM::DataFormat dataFormat = static_cast<CKM::DataFormat>(static_cast<int>(cert->data_format));
	CKM::Certificate ckmCert(buffer, dataFormat);

	CKM::AliasVector ckmUntrustedAliases;
	if(untrustedcerts != NULL) {
		ckmc_alias_list *current = NULL;
		ckmc_alias_list *next = const_cast<ckmc_alias_list *>(untrustedcerts);
		do {
			current = next;
			next = current->next;

			if(current->alias == NULL){
				return CKMC_API_ERROR_INPUT_PARAM;
			}
			CKM::Alias ckmAlias(current->alias);
			ckmUntrustedAliases.push_back(ckmAlias);
		}while(next != NULL);
	}

	if( (ret = mgr.getCertificateChain(ckmCert, ckmUntrustedAliases, ckmCertChain)) != CKMC_API_SUCCESS) {
		return ret;
	}

	*cert_chain_list = _toNewCkmCertList(ckmCertChain);

	return CKMC_API_SUCCESS;
}

