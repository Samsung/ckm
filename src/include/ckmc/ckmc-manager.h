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
 * @version     1.0
 * @brief       Provides management functions(storing, retrieving, and removing) for keys, certificates and data of a user and additional crypto functions.
 */


#ifndef __TIZEN_CORE_CKMC_MANAGER_H
#define __TIZEN_CORE_CKMC_MANAGER_H

#include <stddef.h>
#include <sys/types.h>
#include <tizen.h>
#include <ckmc/ckmc-type.h>
#include <ckmc/ckmc-error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_KEY_MANAGER_CLIENT_MODULE
 * @{
 */


/**
 * @brief Stores a key inside key manager based on the provided policy.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks Currently only four types of keys are supported for this API. These are RSA public/private key and ECDSA /private key.
 * @remarks key_type in key may be set to #CKMC_KEY_NONE as an input. key_type is determined inside key manager during storing keys.
 * @remarks Some private key files are protected by a password. if raw_key in key read from those encrypted files is encrypted with a password, the password should be provided in the #ckmc_key_s structure.
 * @remarks if password in policy is provided, the key is additionally encrypted with the password in policy.
 *
 * @param[in] alias the name of a key to be stored
 * @param[in] key a key's binary value to be stored.
 * @param[in] policy about how to store a key securely.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS alias already exists.
 * @retval #CKMC_ERROR_INVALID_FORMAT the format of raw_key is not valid.
 * @retval #CKMC_ERROR_DB_ERROR failed due to other DB transaction unexpectedly.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_remove_key()
 * @see ckmc_get_key()
 * @see ckmc_get_key_alias_list()
 * @see #ckmc_key_s
 * @see #ckmc_policy_s
 */
int ckmc_save_key(const char *alias, const ckmc_key_s key, const ckmc_policy_s policy);

/**
 * @brief Removes a key from key manager
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks a client can remove only keys stored by the client.
 *
 * @param[in] alias the name of a key to be removed
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_key()
 * @see ckmc_get_key()
 * @see ckmc_get_key_alias_list()
 */
int ckmc_remove_key(const char *alias);

/**
 * @brief Gets a key from key manager
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks a client can access only data stored by the client and non-restricted data stored by other clients.
 * @remarks A newly created ppkey should be destroyed by calling ckmc_key_free() if it is no longer needed.
 *
 * @param[in] alias the name of a key to retrieve
 * @param[in] password used in decrypting a key value. If password of policy is provided in ckmc_save_key(), the same password should be provided.
 * @param[out] ppkey a pointer to a newly created ckmc_key_s handle
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_key()
 * @see ckmc_remove_key()
 * @see ckmc_get_key_alias_list()
 */
int ckmc_get_key(const char *alias, const char *password, ckmc_key_s **ppkey);

/**
 * @brief Gets a all alias of keys to which the client can access
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks a client can access only data stored by the client and non-restricted data stored by other clients.
 * @remarks A newly created ppalias_list should be destroyed by calling ckmc_alias_list_all_free() if it is no longer needed.
 *
 * @param[out] ppalias_list a pointer to a newly created ckmc_alias_list_s handle containing all available alias of keys. If there is no available key alias, *ppalias_list will be null.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_key()
 * @see ckmc_remove_key()
 * @see ckmc_get_key()
 */
int ckmc_get_key_alias_list(ckmc_alias_list_s** ppalias_list);




/**
 * @brief Stores a certificate inside key manager based on the provided policy.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @param[in] alias the name of a certificate to be stored
 * @param[in] cert a certificate's binary value to be stored.
 * @param[in] policy about how to store a certificate securely.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS alias already exists.
 * @retval #CKMC_ERROR_INVALID_FORMAT the format of raw_cert is not valid.
 * @retval #CKMC_ERROR_DB_ERROR failed due to other DB transaction unexpectedly.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_remove_cert()
 * @see ckmc_get_cert()
 * @see ckmc_get_cert_alias_list()
 * @see #ckmc_cert_s
 * @see #ckmc_policy_s
 */
int ckmc_save_cert(const char *alias, const ckmc_cert_s cert, const ckmc_policy_s policy);

/**
 * @brief Removes a certificate from key manager
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks a client can remove only certificates stored by the client.
 *
 * @param[in] alias the name of a certificate to be removed
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_cert()
 * @see ckmc_get_cert()
 * @see ckmc_get_cert_alias_list()
 */
int ckmc_remove_cert(const char *alias);

/**
 * @brief Gets a certificate from key manager
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks a client can access only certificate stored by the client and non-restricted certificate stored by other clients.
 * @remarks A newly created ppcert should be destroyed by calling ckmc_cert_free() if it is no longer needed.
 *
 * @param[in] alias the name of a certificate to retrieve
 * @param[in] password used in decrypting a certificate value. If password of policy is provided in ckmc_save_cert(), the same password should be provided.
 * @param[out] ppcert a pointer to a newly created ckmc_cert_s handle
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_cert()
 * @see ckmc_remove_cert()
 * @see ckmc_get_cert_alias_list()
 */
int ckmc_get_cert(const char *alias, const char *password, ckmc_cert_s **ppcert);

/**
 * @brief Gets a all alias of certificates to which the client can access
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks a client can access only data stored by the client and non-restricted data stored by other clients.
 * @remarks A newly created ppalias_list should be destroyed by calling ckmc_alias_list_all_free() if it is no longer needed.
 *
 * @param[out] ppalias_list a pointer to a newly created ckmc_alias_list_s handle containing all available alias of keys. If there is no available key alias, *ppalias_list will be null.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_cert()
 * @see ckmc_remove_cert()
 * @see ckmc_get_cert()
 */
int ckmc_get_cert_alias_list(ckmc_alias_list_s** ppalias_list);




/**
 * @brief Stores a data inside key manager based on the provided policy.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @param[in] alias the name of a data to be stored
 * @param[in] data a binary value to be stored.
 * @param[in] policy about how to store a data securely.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS alias already exists.
 * @retval #CKMC_ERROR_DB_ERROR failed due to other DB transaction unexpectedly.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_remove_data()
 * @see ckmc_get_data()
 * @see ckmc_get_data_alias_list()
 * @see #ckmc_raw_buffer_s
 * @see #ckmc_policy_s
 */
int ckmc_save_data(const char *alias, ckmc_raw_buffer_s data, const ckmc_policy_s policy);

/**
 * @brief Removes a data from key manager
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks a client can remove only data stored by the client.
 *
 * @param[in] alias the name of a data to be removed
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_data()
 * @see ckmc_get_data()
 * @see ckmc_get_data_alias_list()
 */
int ckmc_remove_data(const char *alias);

/**
 * @brief Gets a data from key manager
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks a client can access only data stored by the client and non-restricted data stored by other clients.
 * @remarks A newly created ppdata should be destroyed by calling ckmc_buffer_free() if it is no longer needed.
 *
 * @param[in] alias the name of a data to retrieve
 * @param[in] password used in decrypting a data value. If password of policy is provided in ckmc_save_data(), the same password should be provided.
 * @param[out] ppdata a pointer to a newly created ckmc_raw_buffer_s handle
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_data()
 * @see ckmc_remove_data()
 * @see ckmc_get_data_alias_list()
 */
int ckmc_get_data(const char *alias, const char *password, ckmc_raw_buffer_s **ppdata);

/**
 * @brief Gets a all alias of data to which the client can access
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks a client can access only data stored by the client and non-restricted data stored by other clients.
 * @remarks A newly created ppalias_list should be destroyed by calling ckmc_alias_list_all_free() if it is no longer needed.
 *
 * @param[out] ppalias_list a pointer to a newly created ckmc_alias_list_s handle containing all available alias of keys. If there is no available key alias, *ppalias_list will be null.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_data()
 * @see ckmc_remove_data()
 * @see ckmc_get_data()
 */
int ckmc_get_data_alias_list(ckmc_alias_list_s** ppalias_list);




/**
 * @brief Creates RSA private/public key pair and stores them inside key manager based on each policy.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks if password in policy is provided, the key is additionally encrypted with the password in policy.
 *
 * @param[in] size the size of key strength to be created. 1024, 2048, and 4096 are supported.
 * @param[in] private_key_alias the name of private key to be stored.
 * @param[in] public_key_alias the name of public key to be stored.
 * @param[in] policy_private_key about how to store a private key securely.
 * @param[in] policy_public_key about how to store a public key securely.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS alias already exists.
 * @retval #CKMC_ERROR_DB_ERROR failed due to other DB transaction unexpectedly.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_create_key_pair_ecdsa()
 * @see ckmc_create_signature()
 * @see ckmc_verify_signature()
 */
int ckmc_create_key_pair_rsa(const size_t size, const char *private_key_alias, const char *public_key_alias, const ckmc_policy_s policy_private_key, const ckmc_policy_s policy_public_key);

/**
 * @brief Creates ECDSA private/public key pair and stores them inside key manager based on each policy.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks if password in policy is provided, the key is additionally encrypted with the password in policy.
 *
 * @param[in] type the type of eliptic curve of ECDSA.
 * @param[in] private_key_alias the name of private key to be stored.
 * @param[in] public_key_alias the name of public key to be stored.
 * @param[in] policy_private_key about how to store a private key securely.
 * @param[in] policy_public_key about how to store a public key securely.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS alias already exists.
 * @retval #CKMC_ERROR_DB_ERROR failed due to other DB transaction unexpectedly.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_create_key_pair_rsa()
 * @see ckmc_create_signature()
 * @see ckmc_verify_signature()
 * @see #ckmc_ec_type_e
 */
int ckmc_create_key_pair_ecdsa(const ckmc_ec_type_e type, const char *private_key_alias, const char *public_key_alias, const ckmc_policy_s policy_private_key, const ckmc_policy_s policy_public_key);

/**
 * @brief Creates a signature on a given message using a private key and returns the signature
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks If password of policy is provided during storing a key, the same password should be provided.
 * @remarks A newly created ppsignature should be destroyed by calling ckmc_buffer_free() if it is no longer needed.
 *
 *
 * @param[in] private_key_alias the name of private key.
 * @param[in] password used in decrypting a private key value.
 * @param[in] message signed with a private key .
 * @param[in] hash the hash algorithm used in creating signature.
 * @param[in] padding the RSA padding algorithm used in creating signature. It is used only when the signature algorithm is RSA.
 * @param[out] ppsignature a pointer to a newly created signature's. If an error occurs, *ppsignature will be null.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_create_key_pair_rsa()
 * @see ckmc_create_key_pair_ecdsa()
 * @see ckmc_verify_signature()
 * @see ckmc_buffer_free()
 * @see #ckmc_hash_algo_e
 * @see #ckmc_rsa_padding_algo_e
 */
int ckmc_create_signature(const char *private_key_alias, const char *password, const ckmc_raw_buffer_s message, const ckmc_hash_algo_e hash, const ckmc_rsa_padding_algo_e padding, ckmc_raw_buffer_s **ppsignature);

/**
 * @brief Verifies a given signature on a given message using a public key and returns the signature status.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks If password of policy is provided during storing a key, the same password should be provided.
 *
 * @param[in] public_key_alias the name of public key.
 * @param[in] password used in decrypting a public key value.
 * @param[in] message a input on which the signature is created.
 * @param[in] signature verified with public key.
 * @param[in] hash the hash algorithm used in verifying signature.
 * @param[in] padding the RSA padding algorithm used in verifying signature. It is used only when the signature algorithm is RSA.
 *
 * @return 0 on success and the signature is valid, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_VERIFICATION_FAILED the signature is invalid
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_create_key_pair_rsa()
 * @see ckmc_create_key_pair_ecdsa()
 * @see ckmc_verify_signature()
 * @see #ckmc_hash_algo_e
 * @see #ckmc_rsa_padding_algo_e
 */
int ckmc_verify_signature(const char *public_key_alias, const char *password, const ckmc_raw_buffer_s message, const ckmc_raw_buffer_s signature, const ckmc_hash_algo_e hash, const ckmc_rsa_padding_algo_e padding);

/**
 * @brief Verifies a certificate chain and return that chain.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.orckmc_buffer_freeg/privilege/keymanager
 *
 * @remarks The trusted root certificate of the chain should exist in the system's certificate storage.
 * @remarks A newly created ppcert_chain_list should be destroyed by calling ckmc_cert_list_all_free() if it is no longer needed.
 *
 * @param[in] cert the certificate to be verified
 * @param[in] untrustedcerts the untrusted CA certificates to be used in verifying a certificate chain.
 * @param[out] ppcert_chain_list a pointer to a newly created certificate chain's handle. If an error occurs, *ppcert_chain_list will be null.
 *
 * @return 0 on success and the signature is valid, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_VERIFICATION_FAILED the certificate chain is not valid
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_INVALID_FORMAT the format of certificate is not valid.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_get_cert_chain_with_alias())
 * @see ckmc_cert_list_all_free()
 */
int ckmc_get_cert_chain(const ckmc_cert_s *cert, const ckmc_cert_list_s *untrustedcerts, ckmc_cert_list_s **ppcert_chain_list);

/**
 * @brief Verifies a certificate chain using a alias list of untrusted certificates and return that chain.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks The trusted root certificate of the chain should exist in the system's certificate storage.
 * @remarks A newly created ppcert_chain_list should be destroyed by calling ckmc_cert_list_all_free() if it is no longer needed.
 *
 * @param[in] cert the certificate to be verified
 * @param[in] untrustedcerts an alias list of untrusted CA certificates stored in key manager to be used in verifying a certificate chain.
 * @param[out] ppcert_chain_list a pointer to a newly created certificate chain's handle. If an error occurs, *ppcert_chain_list will be null.
 *
 * @return 0 on success and the signature is valid, otherwise a negative error value
 * @retval #CKMC_SUCCESS Successful
 * @retval #CKMC_ERROR_VERIFICATION_FAILED the certificate chain is not valid
 * @retval #CKMC_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 * @retval #CKMC_ERROR_INVALID_FORMAT the format of certificate is not valid.
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckmc_get_cert_chain())
 * @see ckmc_cert_list_all_free()
 */
int ckmc_get_cert_chain_with_alias(const ckmc_cert_s *cert, const ckmc_alias_list_s *untrustedcerts, ckmc_cert_list_s **ppcert_chain_list);


#ifdef __cplusplus
}
#endif

/**
 * @}
 */


#endif /* __TIZEN_CORE_CKMC_MANAGER_H */
