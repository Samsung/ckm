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
 * @file        ckmc-type.h
 * @author      Yuseok Jeon(yuseok.jeon@samsung.com)
 * @version     1.0
 * @brief       new and free methods for the struct of CAPI
 */


#include <string.h>
#include <stdlib.h>
#include <ckmc/ckmc-type.h>
#include <ckmc/ckmc-error.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int _ckm_load_cert_from_x509(X509 *xCert, ckm_cert **cert);


KEY_MANAGER_CAPI
ckm_key *ckm_key_new(unsigned char *raw_key, unsigned int key_size, ckm_key_type key_type, char *password)
{
	ckm_key *pkey = new ckm_key;
	if(pkey == NULL)
		return NULL;

	pkey->raw_key = reinterpret_cast<unsigned char*>(malloc(key_size));
	if(pkey->raw_key == NULL) {
		free(pkey);
		return NULL;
	}
	memcpy(pkey->raw_key, raw_key, key_size);

	pkey->key_size = key_size;
	pkey->key_type = key_type;

	if(password != NULL) {
		pkey->password = reinterpret_cast<char*>(malloc(strlen(password) +1));
		if(pkey->password == NULL) {
			free(pkey);
			free(pkey->raw_key);
			return NULL;
		}
		memset(pkey->password, 0, strlen(password) +1);
		strncpy(pkey->password, password, strlen(password));
	}else {
		pkey->password = NULL;
	}

	return pkey;
}

KEY_MANAGER_CAPI
void ckm_key_free(ckm_key *key)
{
	if(key == NULL)
		return;

	if(key->password != NULL)
		free(key->password);
	if(key->raw_key != NULL)
		free(key->raw_key);

	free(key);
}

KEY_MANAGER_CAPI
ckm_raw_buffer * ckm_buffer_new(unsigned char *data, unsigned int size)
{
	ckm_raw_buffer *pbuff = new ckm_raw_buffer;
	if(pbuff == NULL)
			return NULL;

	pbuff->data = reinterpret_cast<unsigned char*>(malloc(size));
	if(pbuff->data == NULL) {
		free(pbuff);
		return NULL;
	}
	memcpy(pbuff->data, data, size);

	pbuff->size = size;

	return pbuff;
}

KEY_MANAGER_CAPI
void ckm_buffer_free(ckm_raw_buffer *buffer)
{
	if(buffer == NULL)
		return;

	if(buffer->data != NULL)
		free(buffer->data);
	free(buffer);
}

KEY_MANAGER_CAPI
ckm_cert *ckm_cert_new(unsigned char *raw_cert, unsigned int cert_size, ckm_cert_form data_format)
{
	ckm_cert *pcert = new ckm_cert;
	if(pcert == NULL)
		return NULL;

	pcert->raw_cert = reinterpret_cast<unsigned char*>(malloc(cert_size));
	if(pcert->raw_cert == NULL) {
		free(pcert);
		return NULL;
	}
	memcpy(pcert->raw_cert, raw_cert, cert_size);

	pcert->cert_size = cert_size;
	pcert->data_format = data_format;

	return pcert;
}

KEY_MANAGER_CAPI
int ckm_load_cert_from_file(const char *file_path, ckm_cert **cert)
{
	OpenSSL_add_all_algorithms();

	FILE *fp = fopen(file_path, "r");
	if(fp == NULL)
		return KEY_MANAGER_API_ERROR_FILE_ACCESS_DENIED;
	X509 *pcert = NULL;
	if(!(pcert = d2i_X509_fp(fp, NULL))) {
		fseek(fp, 0, SEEK_SET);
		pcert = PEM_read_X509(fp, NULL, NULL, NULL);
	}
	fclose(fp);
	if(pcert == NULL) {
		return KEY_MANAGER_API_ERROR_INVALID_FORMAT;
	}

	int ret = _ckm_load_cert_from_x509(pcert, cert);
	if(ret != KEY_MANAGER_API_SUCCESS) {
		X509_free(pcert);
	}
	return ret;
}

KEY_MANAGER_CAPI
int ckm_load_from_pkcs12_file(const char *file_path, const char *passphrase, ckm_key **private_key, ckm_cert **ckmcert, ckm_cert_list **ca_cert_list)
{
	class Pkcs12Converter {
	private:
		FILE* fp_in;
		PKCS12* p12;
		EVP_PKEY* pkey;
		X509* x509Cert;
		STACK_OF(X509)* ca;

	public:
		int ret;
		ckm_key *retPrivateKey;
		ckm_cert *retCkmCert;
		ckm_cert_list *retCaCertList;

		Pkcs12Converter(){
			fp_in = NULL;
			p12 = NULL;
			pkey = NULL;
			x509Cert = NULL;
			ca = NULL;
			ret = KEY_MANAGER_API_SUCCESS;
			retPrivateKey = NULL;
			retCkmCert = NULL;
			retCaCertList = NULL;
		};
		~Pkcs12Converter(){
			if(fp_in != NULL)
				fclose(fp_in);
			if(p12 != NULL)
				PKCS12_free(p12);
			if(x509Cert != NULL)
				X509_free(x509Cert);
			if(pkey != NULL)
				EVP_PKEY_free(pkey);
			if(ca != NULL)
				sk_X509_pop_free(ca, X509_free);
			EVP_cleanup();

			if(ret != KEY_MANAGER_API_SUCCESS) {
				if(retPrivateKey != NULL)
					ckm_key_free(retPrivateKey);
				if(retCkmCert != NULL)
					ckm_cert_free(retCkmCert);
				if(retCaCertList != NULL)
					ckm_cert_list_free(retCaCertList);
			}
		};

		int parsePkcs12(const char *filePath, const char *pass) {
			fp_in = NULL;
			if(!(fp_in = fopen(filePath, "rb"))) {
				return KEY_MANAGER_API_ERROR_FILE_ACCESS_DENIED;
			}

			if(!(p12 = d2i_PKCS12_fp(fp_in, NULL))) {
				return KEY_MANAGER_API_ERROR_INVALID_FORMAT;
			}

			/* parse PKCS#12 certificate */
			if((ret = PKCS12_parse(p12, pass, &pkey, &x509Cert, &ca)) != 1) {
				return KEY_MANAGER_API_ERROR_INVALID_FORMAT;
			}
			return KEY_MANAGER_API_SUCCESS;
		}

		int toCkmCert() {
			if( (ret =_ckm_load_cert_from_x509(x509Cert,&retCkmCert)) != KEY_MANAGER_API_SUCCESS) {
				return ret;
			}
			return KEY_MANAGER_API_SUCCESS;
		}

		int toCkmKey() {
			int prikeyLen = 0;
			if((prikeyLen = i2d_PrivateKey(pkey, NULL)) < 0) {
				return KEY_MANAGER_API_ERROR_OUT_OF_MEMORY;
			}
			unsigned char arrayPrikey[sizeof(unsigned char) * prikeyLen];
			unsigned char *pPrikey = arrayPrikey;
			if((prikeyLen = i2d_PrivateKey(pkey, &pPrikey)) < 0) {
				return KEY_MANAGER_API_ERROR_OUT_OF_MEMORY;
			}

			int type = EVP_PKEY_type(pkey->type);
			ckm_key_type key_type = CKM_KEY_NONE;
			switch(type) {
			case EVP_PKEY_RSA :
				key_type = CKM_KEY_RSA_PRIVATE;
				break;
			case EVP_PKEY_EC :
				key_type = CKM_KEY_ECDSA_PRIVATE;
				break;
			}
			if(key_type == CKM_KEY_NONE) {
				return KEY_MANAGER_API_ERROR_INVALID_FORMAT;
			}

			char *nullPassword = NULL;
			retPrivateKey = ckm_key_new(pPrikey, sizeof(unsigned char) * prikeyLen, key_type, nullPassword);

			return KEY_MANAGER_API_SUCCESS;
		}

		int toCaCkmCertList() {
			X509* popedCert = NULL;
			ckm_cert *popedCkmCert = NULL;
			ckm_cert_list *tmpCertList = NULL;
			retCaCertList = tmpCertList;
			while((popedCert = sk_X509_pop(ca)) != NULL) {
				if( (ret =_ckm_load_cert_from_x509(popedCert, &popedCkmCert)) != KEY_MANAGER_API_SUCCESS) {
					return KEY_MANAGER_API_ERROR_OUT_OF_MEMORY;
				}
				tmpCertList = ckm_cert_list_add(tmpCertList, popedCkmCert);
			}
			return KEY_MANAGER_API_SUCCESS;
		}

	};

	int ret = KEY_MANAGER_API_SUCCESS;

	Pkcs12Converter converter;
	if((ret = converter.parsePkcs12(file_path, passphrase)) != KEY_MANAGER_API_SUCCESS) {
		return ret;
	}
	if((ret = converter.toCkmCert()) != KEY_MANAGER_API_SUCCESS) {
		return ret;
	}
	if((ret = converter.toCkmKey()) != KEY_MANAGER_API_SUCCESS) {
		return ret;
	}
	if((ret = converter.toCaCkmCertList()) != KEY_MANAGER_API_SUCCESS) {
		return ret;
	}
	*private_key = converter.retPrivateKey;
	*ckmcert = converter.retCkmCert;
	*ca_cert_list = converter.retCaCertList;

	return KEY_MANAGER_API_SUCCESS;
}

KEY_MANAGER_CAPI
void ckm_cert_free(ckm_cert *cert)
{
	if(cert == NULL)
		return;

	if(cert->raw_cert != NULL)
		free(cert->raw_cert);
	free(cert);
}

KEY_MANAGER_CAPI
ckm_alias_list *ckm_alias_list_new(char *alias)
{
	ckm_alias_list *previous = NULL;
	return ckm_alias_list_add(previous, alias);
}

KEY_MANAGER_CAPI
ckm_alias_list *ckm_alias_list_add(ckm_alias_list *previous, char *alias)
{
	ckm_alias_list *plist = new ckm_alias_list;

	plist->alias = alias;
	plist->next = NULL;

	if(previous != NULL)
		previous->next = plist;

	return plist;
}

KEY_MANAGER_CAPI
void ckm_alias_list_free(ckm_alias_list *first)
{
	if(first == NULL)
		return;

	ckm_alias_list *current = NULL;
	ckm_alias_list *next = first;
	do {
		current = next;
		next = current->next;
		free(current);
	}while(next != NULL);
}

KEY_MANAGER_CAPI
void ckm_alias_list_all_free(ckm_alias_list *first)
{
	if(first == NULL)
		return;

	ckm_alias_list *current = NULL;
	ckm_alias_list *next = first;
	do {
		current = next;
		next = current->next;
		if((current->alias)!=NULL) {
			free(current->alias);
		}
		free(current);
	}while(next != NULL);
}

KEY_MANAGER_CAPI
ckm_cert_list *ckm_cert_list_new(ckm_cert *cert)
{
	ckm_cert_list *previous = NULL;
	return ckm_cert_list_add(previous, cert);
}

KEY_MANAGER_CAPI
ckm_cert_list *ckm_cert_list_add(ckm_cert_list *previous, ckm_cert *cert)
{
	ckm_cert_list *plist = new ckm_cert_list;

	plist->cert = cert;
	plist->next = NULL;

	if(previous != NULL)
		previous->next = plist;

	return plist;
}

KEY_MANAGER_CAPI
void ckm_cert_list_free(ckm_cert_list *first)
{
	if(first == NULL)
		return;

	ckm_cert_list *current = NULL;
	ckm_cert_list *next = first;
	do {
		current = next;
		next = current->next;
		free(current);
	}while(next != NULL);
}

KEY_MANAGER_CAPI
void ckm_cert_list_all_free(ckm_cert_list *first)
{
	if(first == NULL)
		return;

	ckm_cert_list *current = NULL;
	ckm_cert_list *next = first;
	do {
		current = next;
		next = current->next;
		if((current->cert)!=NULL) {
			ckm_cert_free(current->cert);
		}
		free(current);
	}while(next != NULL);
}

int _ckm_load_cert_from_x509(X509 *xCert, ckm_cert **cert)
{
	int certLen;
	unsigned char* bufCert = NULL;

	if(xCert == NULL) {
		return KEY_MANAGER_API_ERROR_INVALID_FORMAT;
	}

	/* load certificate into buffer */
	if((certLen = i2d_X509(xCert, NULL)) < 0) {
		return KEY_MANAGER_API_ERROR_INVALID_FORMAT;
	}
	unsigned char arrayCert[sizeof(unsigned char) * certLen];
	bufCert = arrayCert;
	i2d_X509(xCert, &bufCert);

	*cert = ckm_cert_new(bufCert, certLen, CKM_CERT_FORM_DER);

	return KEY_MANAGER_API_SUCCESS;
}
