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

bool _toBool(ckm_bool ckmBool)
{
	if(ckmBool == CKM_TRUE) {
		return true;
	}
	return false;
}

CKM::Certificate _toCkmCertificate(const ckm_cert *cert)
{
	CKM::RawBuffer buffer(cert->raw_cert, cert->raw_cert + cert->cert_size);
	CKM::DataFormat dataFormat = static_cast<CKM::DataFormat>(static_cast<int>(cert->data_format));
	CKM::Certificate ckmCert(buffer, dataFormat);
	return ckmCert;
}

ckm_cert_list *_toNewCkmCertList(CKM::CertificateVector &certVector)
{
	ckm_cert_list *start = NULL;
	ckm_cert_list *plist = NULL;
	CKM::CertificateVector::iterator it;
	for(it = certVector.begin(); it != certVector.end(); it++) {
		CKM::RawBuffer rawBuffer = it->getDER();
		unsigned char *rawCert = reinterpret_cast<unsigned char*>(rawBuffer.data());
		ckm_cert *pcert = ckm_cert_new( rawCert, rawBuffer.size(), CKM_CERT_FORM_DER);
		if(pcert == NULL) {
			return NULL;
		}
		if(plist == NULL) {
			plist = ckm_cert_list_new(pcert);
			start = plist; // save the pointer of the first element
		}else {
			plist = ckm_cert_list_add(plist, pcert);
		}
	}
	return start;
}

KEY_MANAGER_CAPI
int ckm_save_key(const char *alias, const ckm_key key, const ckm_policy policy)
{
	CKM::Manager mgr;

	if(alias == NULL) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	if(key.raw_key == NULL || key.key_size <= 0) {
			return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::RawBuffer buffer(key.raw_key, key.raw_key + key.key_size);
	std::string password(key.password);
	CKM::Key ckmKey(buffer,password);

	CKM::Policy storePolicy(policy.password, _toBool(policy.extractable), _toBool(policy.restricted));

	return mgr.saveKey(ckmAlias, ckmKey, storePolicy);
}


KEY_MANAGER_CAPI
int ckm_remove_key(const char *alias)
{
	CKM::Manager mgr;

	if(alias == NULL) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	return mgr.removeKey(ckmAlias);
}

KEY_MANAGER_CAPI
int ckm_get_key(const char *alias, const char *password, ckm_key **key)
{
	int ret;
	CKM::Key ckmKey;

	if(alias == NULL) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	CKM::Manager mgr;
	if( (ret = mgr.getKey(ckmAlias, std::string(password), ckmKey)) != CKM_API_SUCCESS) {
		return ret;
	}

	unsigned char *rawKey = reinterpret_cast<unsigned char*>(ckmKey.getDER().data());
	ckm_key_type keyType = static_cast<ckm_key_type>(static_cast<int>(ckmKey.getType()));
	*key = ckm_key_new( rawKey, ckmKey.getDER().size(), keyType, NULL);
	if(*key == NULL) {
		return CKM_API_ERROR_OUT_OF_MEMORY;
	}else {
		return CKM_API_SUCCESS;
	}
}

KEY_MANAGER_CAPI
int ckm_get_key_alias_list(const ckm_alias_list** alias_list)
{
	int ret;
	CKM::Key ckmKey;

	CKM::AliasVector aliasVector;
	CKM::Manager mgr;
	if( (ret = mgr.getKeyAliasVector(aliasVector)) != CKM_API_SUCCESS) {
		return ret;
	}

	ckm_alias_list *plist = NULL;
	CKM::AliasVector::iterator it;
	for(it = aliasVector.begin(); it != aliasVector.end(); it++) {
		if(plist == NULL) { // first
			plist = ckm_alias_list_new(const_cast<char *>(it->c_str()));
			*alias_list = plist; // save the pointer of the first element
		}else {
			plist = ckm_alias_list_add(plist, const_cast<char *>(it->c_str()));
		}
	}

	return CKM_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckm_save_cert(const char *alias, const ckm_cert cert, const ckm_policy policy)
{
	if(alias == NULL) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	if(cert.raw_cert == NULL || cert.cert_size <= 0) {
			return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::Certificate ckmCert = _toCkmCertificate(&cert);

	CKM::Policy storePolicy(policy.password, _toBool(policy.extractable), _toBool(policy.restricted));

	CKM::Manager mgr;
	return mgr.saveCertificate(ckmAlias, ckmCert, storePolicy);
}

KEY_MANAGER_CAPI
int ckm_remove_cert(const char *alias)
{
	if(alias == NULL) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	CKM::Manager mgr;
	return mgr.removeCertificate(ckmAlias);
}

KEY_MANAGER_CAPI
int ckm_get_cert(const char *alias, const char *password, const ckm_cert **cert)
{
	CKM::Certificate ckmCert;
	int ret;

	if(alias == NULL) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	CKM::Manager mgr;
	if( (ret = mgr.getCertificate(ckmAlias, std::string(password), ckmCert)) != CKM_API_SUCCESS) {
		return ret;
	}

	unsigned char *rawCert = reinterpret_cast<unsigned char*>(ckmCert.getDER().data());
	*cert = ckm_cert_new( rawCert, ckmCert.getDER().size(), CKM_CERT_FORM_DER);
	if(*cert == NULL) {
		return CKM_API_ERROR_OUT_OF_MEMORY;
	}else {
		return CKM_API_SUCCESS;
	}
}

KEY_MANAGER_CAPI
int ckm_get_cert_alias_list(const ckm_alias_list** alias_list) {
	int ret;
	CKM::Key ckmKey;

	CKM::AliasVector aliasVector;
	CKM::Manager mgr;
	if( (ret = mgr.getCertificateAliasVector(aliasVector)) != CKM_API_SUCCESS) {
		return ret;
	}

	ckm_alias_list *plist = NULL;
	CKM::AliasVector::iterator it;
	for(it = aliasVector.begin(); it != aliasVector.end(); it++) {
		if(plist == NULL) { // first
			plist = ckm_alias_list_new(const_cast<char *>(it->c_str()));
			*alias_list = plist; // save the pointer of the first element
		}else {
			plist = ckm_alias_list_add(plist, const_cast<char *>(it->c_str()));
		}
	}

	return CKM_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckm_save_data(const char *alias, ckm_raw_buffer data, const ckm_policy policy)
{
	if(alias == NULL) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	if(data.data == NULL || data.size <= 0) {
			return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::RawBuffer buffer(data.data, data.data + data.size);

	CKM::Policy storePolicy(policy.password, _toBool(policy.extractable), _toBool(policy.restricted));

	CKM::Manager mgr;
	return mgr.saveData(ckmAlias, buffer, storePolicy);
}

KEY_MANAGER_CAPI
int ckm_remove_data(const char *alias)
{
	if(alias == NULL) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	CKM::Manager mgr;
	return mgr.removeData(ckmAlias);
}

KEY_MANAGER_CAPI
int ckm_get_data(const char *alias, const char *password, ckm_raw_buffer **data)
{
	CKM::RawBuffer ckmBuff;
	int ret;

	if(alias == NULL) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::Alias ckmAlias(alias);

	CKM::Manager mgr;
	if( (ret = mgr.getData(ckmAlias, std::string(password), ckmBuff)) != CKM_API_SUCCESS) {
		return ret;
	}

	unsigned char *rawBuff = reinterpret_cast<unsigned char*>(ckmBuff.data());
	*data = ckm_buffer_new( rawBuff, ckmBuff.size());
	if(*data == NULL) {
		return CKM_API_ERROR_OUT_OF_MEMORY;
	}else {
		return CKM_API_SUCCESS;
	}
}

KEY_MANAGER_CAPI
int ckm_get_data_alias_list(const ckm_alias_list** alias_list){
	int ret;
	CKM::Key ckmKey;

	CKM::AliasVector aliasVector;
	CKM::Manager mgr;
	if( (ret = mgr.getDataAliasVector(aliasVector)) != CKM_API_SUCCESS) {
		return ret;
	}

	ckm_alias_list *plist = NULL;
	CKM::AliasVector::iterator it;
	for(it = aliasVector.begin(); it != aliasVector.end(); it++) {
		if(plist == NULL) { // first
			plist = ckm_alias_list_new(const_cast<char *>(it->c_str()));
			*alias_list = plist; // save the pointer of the first element
		}else {
			plist = ckm_alias_list_add(plist, const_cast<char *>(it->c_str()));
		}
	}

	return CKM_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckm_create_key_pair_rsa(const int size,
							const char *private_key_alias,
							const char *public_key_alias,
							const ckm_policy policy_private_key,
							const ckm_policy policy_public_key)
{
	int ret;
	CKM::Manager mgr;

	CKM::Alias ckmPrivakeKeyAlias(private_key_alias);
	CKM::Alias ckmPublicKeyAlias(public_key_alias);
	CKM::Policy ckmPrivateKeyPolicy(policy_private_key.password, _toBool(policy_private_key.extractable), _toBool(policy_private_key.restricted));
	CKM::Policy ckmPublicKeyPolicy(policy_public_key.password, _toBool(policy_public_key.extractable), _toBool(policy_public_key.restricted));

	if( (mgr.createKeyPairRSA(size, ckmPrivakeKeyAlias, ckmPublicKeyAlias, ckmPrivateKeyPolicy, ckmPublicKeyPolicy))
			!= CKM_API_SUCCESS) {
		return ret;
	}

	return CKM_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckm_create_key_pair_ecdsa(const ckm_ec_type type,
							const char *private_key_alias,
							const char *public_key_alias,
							const ckm_policy policy_private_key,
							const ckm_policy policy_public_key)
{
	int ret;
	CKM::Manager mgr;

	CKM::ElipticCurve ckmType = static_cast<CKM::ElipticCurve>(static_cast<int>(type));
	CKM::Alias ckmPrivakeKeyAlias(private_key_alias);
	CKM::Alias ckmPublicKeyAlias(public_key_alias);
	CKM::Policy ckmPrivateKeyPolicy(policy_private_key.password, _toBool(policy_private_key.extractable), _toBool(policy_private_key.restricted));
	CKM::Policy ckmPublicKeyPolicy(policy_public_key.password, _toBool(policy_public_key.extractable), _toBool(policy_public_key.restricted));

	if( (mgr.createKeyPairECDSA(ckmType, ckmPrivakeKeyAlias, ckmPublicKeyAlias, ckmPrivateKeyPolicy, ckmPublicKeyPolicy))
			!= CKM_API_SUCCESS) {
		return ret;
	}

	return CKM_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckm_create_signature(const char *private_key_alias,
							const char *password,
							const ckm_raw_buffer message,
							const ckm_hash_algo hash,
							const ckm_rsa_padding_algo padding,
							ckm_raw_buffer **signature)
{
	int ret;
	CKM::Manager mgr;
	CKM::RawBuffer ckmSignature;

	CKM::Alias ckmPrivakeKeyAlias(private_key_alias);
	CKM::RawBuffer ckmMessage(message.data, message.data + message.size);
	CKM::HashAlgorithm ckmHashAlgo = static_cast<CKM::HashAlgorithm>(static_cast<int>(hash));
	CKM::RSAPaddingAlgorithm ckmPadding = static_cast<CKM::RSAPaddingAlgorithm>(static_cast<int>(padding));

	if( (ret = mgr.createSignature(
			ckmPrivakeKeyAlias,
			password,
			ckmMessage,
			ckmHashAlgo,
			ckmPadding,
			ckmSignature)) != CKM_API_SUCCESS) {
		return ret;
	}

	unsigned char *rawBuff = reinterpret_cast<unsigned char*>(ckmSignature.data());
	*signature = ckm_buffer_new( rawBuff, ckmSignature.size());
	if(*signature == NULL) {
		return CKM_API_ERROR_OUT_OF_MEMORY;
	}else {
		return CKM_API_SUCCESS;
	}

	return CKM_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckm_verify_signature(const char *public_key_alias,
							const char *password,
							const ckm_raw_buffer message,
							const ckm_raw_buffer signature,
							const ckm_hash_algo hash,
							const ckm_rsa_padding_algo padding)
{
	int ret;
	CKM::Manager mgr;

	CKM::Alias ckmPublicKeyAlias(public_key_alias);
	CKM::RawBuffer ckmMessage(message.data, message.data + message.size);
	CKM::RawBuffer ckmSignature(signature.data, signature.data + signature.size);
	CKM::HashAlgorithm ckmHashAlgo = static_cast<CKM::HashAlgorithm>(static_cast<int>(hash));
	CKM::RSAPaddingAlgorithm ckmPadding = static_cast<CKM::RSAPaddingAlgorithm>(static_cast<int>(padding));

	if( (ret = mgr.verifySignature(
			ckmPublicKeyAlias,
			password,
			ckmMessage,
			ckmSignature,
			ckmHashAlgo,
			ckmPadding)) != CKM_API_SUCCESS) {
		return ret;
	}

	return CKM_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckm_get_cert_chain(const ckm_cert *cert, const ckm_cert_list *untrustedcerts, ckm_cert_list **cert_chain_list)
{
	int ret;
	CKM::Manager mgr;
	CKM::CertificateVector ckmCertChain;


	if(cert->raw_cert == NULL || cert->cert_size <= 0) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::RawBuffer buffer(cert->raw_cert, cert->raw_cert + cert->cert_size);
	CKM::DataFormat dataFormat = static_cast<CKM::DataFormat>(static_cast<int>(cert->data_format));
	CKM::Certificate ckmCert(buffer, dataFormat);

	CKM::CertificateVector ckmUntrustedCerts;
	if(untrustedcerts != NULL) {
		ckm_cert_list *current = NULL;
		ckm_cert_list *next = const_cast<ckm_cert_list *>(untrustedcerts);
		do {
			current = next;
			next = current->next;

			if(current->cert == NULL){
				return CKM_API_ERROR_INPUT_PARAM;
			}
			CKM::Certificate ckmCert = _toCkmCertificate(current->cert);
			ckmUntrustedCerts.push_back(ckmCert);
		}while(next != NULL);
	}

	if( (ret = mgr.getCertificateChain(ckmCert, ckmUntrustedCerts, ckmCertChain)) != CKM_API_SUCCESS) {
		return ret;
	}

	*cert_chain_list = _toNewCkmCertList(ckmCertChain);

	return CKM_API_SUCCESS;
}

KEY_MANAGER_CAPI
int ckm_get_cert_chain_with_alias(const ckm_cert *cert, const ckm_alias_list *untrustedcerts, ckm_cert_list **cert_chain_list)
{
	int ret;
	CKM::Manager mgr;
	CKM::CertificateVector ckmCertChain;


	if(cert->raw_cert == NULL || cert->cert_size <= 0) {
		return CKM_API_ERROR_INPUT_PARAM;
	}
	CKM::RawBuffer buffer(cert->raw_cert, cert->raw_cert + cert->cert_size);
	CKM::DataFormat dataFormat = static_cast<CKM::DataFormat>(static_cast<int>(cert->data_format));
	CKM::Certificate ckmCert(buffer, dataFormat);

	CKM::AliasVector ckmUntrustedAliases;
	if(untrustedcerts != NULL) {
		ckm_alias_list *current = NULL;
		ckm_alias_list *next = const_cast<ckm_alias_list *>(untrustedcerts);
		do {
			current = next;
			next = current->next;

			if(current->alias == NULL){
				return CKM_API_ERROR_INPUT_PARAM;
			}
			CKM::Alias ckmAlias(current->alias);
			ckmUntrustedAliases.push_back(ckmAlias);
		}while(next != NULL);
	}

	if( (ret = mgr.getCertificateChain(ckmCert, ckmUntrustedAliases, ckmCertChain)) != CKM_API_SUCCESS) {
		return ret;
	}

	*cert_chain_list = _toNewCkmCertList(ckmCertChain);

	return CKM_API_SUCCESS;
}

