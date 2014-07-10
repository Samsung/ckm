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
 * @brief       Definitions of struct for CAPI
 */

#ifndef CKMC_TYPE_H
#define CKMC_TYPE_H

#include <stddef.h>

#define KEY_MANAGER_CAPI __attribute__((visibility("default")))


#ifdef __cplusplus
extern "C" {
#endif

typedef enum ckm_key_type_t {
    CKM_KEY_NONE,
    CKM_KEY_RSA_PUBLIC,
    CKM_KEY_RSA_PRIVATE,
    CKM_KEY_ECDSA_PUBLIC,
    CKM_KEY_ECDSA_PRIVATE,
    CKM_KEY_AES
} ckm_key_type;

typedef enum ckm_data_format_t {
	CKM_FORM_DER_BASE64,
	CKM_FORM_DER,
	CKM_FORM_PEM
} ckm_data_format;

typedef enum ckm_ec_type_t {
	CKM_EC_PRIME192V1,
	CKM_EC_PRIME256V1,
	CKM_EC_SECP384R1
} ckm_ec_type;

typedef enum ckm_bool_t {
	CKM_FALSE,
	CKM_TRUE
} ckm_bool;

typedef enum ckm_hash_algo_t {
	CKM_HASH_SHA1,
	CKM_HASH_SHA256,
	CKM_HASH_SHA384,
	CKM_HASH_SHA512
} ckm_hash_algo;

typedef enum ckm_rsa_padding_algo_t {
    CKM_PKCS1_PADDING,
    CKM_X931_PADDING
} ckm_rsa_padding_algo;

typedef struct ckm_raw_buff_t{
	unsigned char* data;
	size_t         size;
} ckm_raw_buffer;

typedef struct ckm_policy_t {
	char*          password;  // byte array used to encrypt data inside CKM
	ckm_bool       extractable;  // if true key may be extracted from storage
	ckm_bool       restricted;   // if true only key owner may see data
} ckm_policy;

typedef struct ckm_key_t {
	unsigned char* raw_key;
	size_t         key_size;
	ckm_key_type   key_type;
	char*          password;  // byte array used to encrypt data inside CKM
} ckm_key;

typedef struct ckm_cert_t {
	unsigned char*  raw_cert;
	size_t          cert_size;
	ckm_data_format data_format;
} ckm_cert;

typedef struct ckm_alias_list_t {
	char *alias;
	struct ckm_alias_list_t *next;
} ckm_alias_list;

typedef struct ckm_cert_list_t {
	ckm_cert *cert;
	struct ckm_cert_list_t *next;
} ckm_cert_list;


ckm_key *ckm_key_new(unsigned char *raw_key, size_t key_size, ckm_key_type key_type, char *password);
void ckm_key_free(ckm_key *key);

ckm_raw_buffer * ckm_buffer_new(unsigned char *data, size_t size);
void ckm_buffer_free(ckm_raw_buffer *buffer);

ckm_cert *ckm_cert_new(unsigned char *raw_cert, size_t cert_size, ckm_data_format data_format);

void ckm_cert_free(ckm_cert *cert);

int ckm_load_cert_from_file(const char *file_path, ckm_cert **cert);
int ckm_load_from_pkcs12_file(const char *file_path, const char *passphrase, ckm_key **private_key, ckm_cert **cert, ckm_cert_list **ca_cert_list);

ckm_alias_list *ckm_alias_list_new(char *alias);
ckm_alias_list *ckm_alias_list_add(ckm_alias_list *previous, char *alias);
void ckm_alias_list_free(ckm_alias_list *first);
void ckm_alias_list_all_free(ckm_alias_list *cert_list);

ckm_cert_list *ckm_cert_list_new(ckm_cert *cert);
ckm_cert_list *ckm_cert_list_add(ckm_cert_list *previous, ckm_cert *cert);
void ckm_cert_list_free(ckm_cert_list *first);
void ckm_cert_list_all_free(ckm_cert_list *cert_list);


#ifdef __cplusplus
}
#endif

#endif /* CKMC_TYPE_H */
