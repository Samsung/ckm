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
 * @file        ckmc-manager.h
 * @author      Yuseok Jeon(yuseok.jeon@samsung.com)
 * @version     1.0
 * @brief       provides management functions(storing, retrieving, and removing) for keys, certificates and data of a user and additional crypto functions.
 */


#ifndef CKMC_MANAGER_H
#define CKMC_MANAGER_H

#include <sys/types.h>
#include <ckmc/ckmc-type.h>

#ifdef __cplusplus
extern "C" {
#endif

// key related functions
int ckm_save_key(const char *alias, const ckm_key key, const ckm_policy policy);
int ckm_remove_key(const char *alias);
int ckm_get_key(const char *alias, const char *password, ckm_key **key);
int ckm_get_key_alias_list(const ckm_alias_list** alias_list);

int ckm_save_cert(const char *alias, const ckm_cert cert, const ckm_policy policy);
int ckm_remove_cert(const char *alias);
int ckm_get_cert(const char *alias, const char *password, const ckm_cert **cert);
int ckm_get_cert_alias_list(const ckm_alias_list** alias_list);

int ckm_save_data(const char *alias, ckm_raw_buffer data, const ckm_policy policy);
int ckm_remove_data(const char *alias);
int ckm_get_data(const char *alias, const char *password, ckm_raw_buffer **data);
int ckm_get_data_alias_list(const ckm_alias_list** alias_list);


// crypto functions
int ckm_create_key_pair_rsa(const int size, const char *private_key_alias, const char *public_key_alias, const ckm_policy policy_private_key, const ckm_policy policy_public_key);
int ckm_create_key_pair_ecdsa(const ckm_ec_type type, const char *private_key_alias, const char *public_key_alias, const ckm_policy policy_private_key, const ckm_policy policy_public_key);
int ckm_create_signature(const char *private_key_alias, const char *password, const ckm_raw_buffer message, const ckm_hash_algo hash, const ckm_rsa_padding_algo padding, ckm_raw_buffer **signature);
int ckm_verify_signature(const char *public_key_alias, const char *password, const ckm_raw_buffer message, const ckm_raw_buffer signature, const ckm_hash_algo hash, const ckm_rsa_padding_algo padding);

int ckm_get_cert_chain(const ckm_cert *cert, const ckm_cert_list *untrustedcerts, ckm_cert_list **cert_chain_list);
int ckm_get_cert_chain_with_alias(const ckm_cert *cert, const ckm_alias_list *untrustedcerts, ckm_cert_list **cert_chain_list);


#ifdef __cplusplus
}
#endif


#endif /* CKMC_MANAGER_H */
