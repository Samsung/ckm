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
 * @brief       provides management functions(storing, retrieving, and removing) for keys, certificates and data of a user and additional crypto functions.
 */


#ifndef __TIZEN_CORE_CKMC_MANAGER_H
#define __TIZEN_CORE_CKMC_MANAGER_H

#include <stddef.h>
#include <sys/types.h>
#include <ckmc/ckmc-type.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_KEY_MANAGER_MODULE
 * @{
 */


/**
 * @brief Stores a key inside key manager based on the provided policy.
 *
 * @remarks Currently only four types of keys are supported for this API. These are RSA public/private key and ECDSA /private key.
 * @remarks key_type in key may be set to #CKM_KEY_NONE as an input. key_type is determined inside key manager during storing keys.
 * @remarks Some private key files are protected by a password. if raw_key in key read from those encrypted files is encrypted with a password, the password should be provided in the #ckm_key structure.
 * @remarks if password in policy is provided, the key is additionally encrypted with the password in policy.
 *
 * @param[in] alias is the name of a key to be stored
 * @param[in] key has a key's binary value to be stored.
 * @param[in] policy is about how to store a key securely.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ALIAS_EXISTS alias already exists.
 * @retval #CKM_API_ERROR_INVALID_FORMAT the format of raw_key is not valid.
 * @retval #CKM_API_ERROR_DB_ERROR failed due to other DB transaction unexpectedly.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_remove_key()
 * @see ckm_get_key()
 * @see ckm_get_key_alias_list()
 * @see #ckm_key
 * @see #ckm_policy
 */
int ckm_save_key(const char *alias, const ckm_key key, const ckm_policy policy);

/**
 * @brief Removes a key from key manager
 *
 * @remarks a client can remove only keys stored by the client.
 *
 * @param[in] alias is the name of a key to be removed
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_save_key()
 * @see ckm_get_key()
 * @see ckm_get_key_alias_list()
 */
int ckm_remove_key(const char *alias);

/**
 * @brief Get a key from key manager
 *
 * @remarks a client can access only data stored by the client and non-restricted data stored by other clients.
 * @remarks A newly created ppkey should be destroyed by calling ckm_key_free() if it is no longer needed.
 *
 * @param[in] alias is the name of a key to retrieve
 * @param[in] password is used in decrypting a key value. If password of policy is provided in ckm_save_key(), the same password should be provided.
 * @param[out] ppkey is a pointer to a newly created ckm_key handle
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_save_key()
 * @see ckm_remove_key()
 * @see ckm_get_key_alias_list()
 */
int ckm_get_key(const char *alias, const char *password, ckm_key **ppkey);

/**
 * @brief Get a all alias of keys to which the client can access
 *
 * @remarks a client can access only data stored by the client and non-restricted data stored by other clients.
 * @remarks A newly created ppalias_list should be destroyed by calling ckm_alias_list_all_free() if it is no longer needed.
 *
 * @param[out] ppalias_list is a pointer to a newly created ckm_alias_list handle containing all available alias of keys. If there is no available key alias, *ppalias_list will be null.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_save_key()
 * @see ckm_remove_key()
 * @see ckm_get_key()
 */
int ckm_get_key_alias_list(ckm_alias_list** ppalias_list);




/**
 * @brief Stores a certificate inside key manager based on the provided policy.
 *
 * @param[in] alias is the name of a certificate to be stored
 * @param[in] cert has a certificate's binary value to be stored.
 * @param[in] policy is about how to store a certificate securely.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ALIAS_EXISTS alias already exists.
 * @retval #CKM_API_ERROR_INVALID_FORMAT the format of raw_cert is not valid.
 * @retval #CKM_API_ERROR_DB_ERROR failed due to other DB transaction unexpectedly.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_remove_cert()
 * @see ckm_get_cert()
 * @see ckm_get_cert_alias_list()
 * @see #ckm_cert
 * @see #ckm_policy
 */
int ckm_save_cert(const char *alias, const ckm_cert cert, const ckm_policy policy);

/**
 * @brief Removes a certificate from key manager
 *
 * @remarks a client can remove only certificates stored by the client.
 *
 * @param[in] alias is the name of a certificate to be removed
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_save_cert()
 * @see ckm_get_cert()
 * @see ckm_get_cert_alias_list()
 */
int ckm_remove_cert(const char *alias);

/**
 * @brief Get a certificate from key manager
 *
 * @remarks a client can access only certificate stored by the client and non-restricted certificate stored by other clients.
 * @remarks A newly created ppcert should be destroyed by calling ckm_cert_free() if it is no longer needed.
 *
 * @param[in] alias is the name of a certificate to retrieve
 * @param[in] password is used in decrypting a certificate value. If password of policy is provided in ckm_save_cert(), the same password should be provided.
 * @param[out] ppcert is a pointer to a newly created ckm_cert handle
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_save_cert()
 * @see ckm_remove_cert()
 * @see ckm_get_cert_alias_list()
 */
int ckm_get_cert(const char *alias, const char *password, const ckm_cert **ppcert);

/**
 * @brief Get a all alias of certificates to which the client can access
 *
 * @remarks a client can access only data stored by the client and non-restricted data stored by other clients.
 * @remarks A newly created ppalias_list should be destroyed by calling ckm_alias_list_all_free() if it is no longer needed.
 *
 * @param[out] ppalias_list is a pointer to a newly created ckm_alias_list handle containing all available alias of keys. If there is no available key alias, *ppalias_list will be null.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_save_cert()
 * @see ckm_remove_cert()
 * @see ckm_get_cert()
 */
int ckm_get_cert_alias_list(ckm_alias_list** ppalias_list);




/**
 * @brief Stores a data inside key manager based on the provided policy.
 *
 * @param[in] alias is the name of a data to be stored
 * @param[in] data has a binary value to be stored.
 * @param[in] policy is about how to store a data securely.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ALIAS_EXISTS alias already exists.
 * @retval #CKM_API_ERROR_DB_ERROR failed due to other DB transaction unexpectedly.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_remove_data()
 * @see ckm_get_data()
 * @see ckm_get_data_alias_list()
 * @see #ckm_raw_buffer
 * @see #ckm_policy
 */
int ckm_save_data(const char *alias, ckm_raw_buffer data, const ckm_policy policy);

/**
 * @brief Removes a data from key manager
 *
 * @remarks a client can remove only data stored by the client.
 *
 * @param[in] alias is the name of a data to be removed
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_save_data()
 * @see ckm_get_data()
 * @see ckm_get_data_alias_list()
 */
int ckm_remove_data(const char *alias);

/**
 * @brief Get a data from key manager
 *
 * @remarks a client can access only data stored by the client and non-restricted data stored by other clients.
 * @remarks A newly created ppdata should be destroyed by calling ckm_buffer_free() if it is no longer needed.
 *
 * @param[in] alias is the name of a data to retrieve
 * @param[in] password is used in decrypting a data value. If password of policy is provided in ckm_save_data(), the same password should be provided.
 * @param[out] ppdata is a pointer to a newly created ckm_raw_buffer handle
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_save_data()
 * @see ckm_remove_data()
 * @see ckm_get_data_alias_list()
 */
int ckm_get_data(const char *alias, const char *password, ckm_raw_buffer **ppdata);

/**
 * @brief Get a all alias of data to which the client can access
 *
 * @remarks a client can access only data stored by the client and non-restricted data stored by other clients.
 * @remarks A newly created ppalias_list should be destroyed by calling ckm_alias_list_all_free() if it is no longer needed.
 *
 * @param[out] ppalias_list is a pointer to a newly created ckm_alias_list handle containing all available alias of keys. If there is no available key alias, *ppalias_list will be null.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ERROR failed due to the error with unknown reason
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_save_data()
 * @see ckm_remove_data()
 * @see ckm_get_data()
 */
int ckm_get_data_alias_list(ckm_alias_list** ppalias_list);




/**
 * @brief Creates RSA private/public key pair and stores them inside key manager based on each policy.
 *
 * @remarks if password in policy is provided, the key is additionally encrypted with the password in policy.
 *
 * @param[in] size is the size of key strength to be created. 1024, 2048, and 4096 are supported.
 * @param[in] private_key_alias is the name of private key to be stored.
 * @param[in] public_key_alias is the name of public key to be stored.
 * @param[in] policy_private_key is about how to store a private key securely.
 * @param[in] policy_public_key is about how to store a public key securely.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ALIAS_EXISTS alias already exists.
 * @retval #CKM_API_ERROR_DB_ERROR failed due to other DB transaction unexpectedly.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_create_key_pair_ecdsa()
 * @see ckm_create_signature()
 * @see ckm_verify_signature()
 */
int ckm_create_key_pair_rsa(const size_t size, const char *private_key_alias, const char *public_key_alias, const ckm_policy policy_private_key, const ckm_policy policy_public_key);

/**
 * @brief Creates ECDSA private/public key pair and stores them inside key manager based on each policy.
 *
 * @remarks if password in policy is provided, the key is additionally encrypted with the password in policy.
 *
 * @param[in] type is the type of eliptic curve of ECDSA.
 * @param[in] private_key_alias is the name of private key to be stored.
 * @param[in] public_key_alias is the name of public key to be stored.
 * @param[in] policy_private_key is about how to store a private key securely.
 * @param[in] policy_public_key is about how to store a public key securely.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ALIAS_EXISTS alias already exists.
 * @retval #CKM_API_ERROR_DB_ERROR failed due to other DB transaction unexpectedly.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_create_key_pair_rsa()
 * @see ckm_create_signature()
 * @see ckm_verify_signature()
 * @see #ckm_ec_type
 */
int ckm_create_key_pair_ecdsa(const ckm_ec_type type, const char *private_key_alias, const char *public_key_alias, const ckm_policy policy_private_key, const ckm_policy policy_public_key);

/**
 * @brief Creates a signature on a given message using a private key and returns the signature
 *
 * @remarks If password of policy is provided during storing a key, the same password should be provided.
 * @remarks A newly created ppsignature should be destroyed by calling ckm_buffer_free() if it is no longer needed.
 *
 *
 * @param[in] private_key_alias is the name of private key.
 * @param[in] password is used in decrypting a private key value.
 * @param[in] message is signed with a private key .
 * @param[in] hash is the hash algorithm used in creating signature.
 * @param[in] padding is the RSA padding algorithm used in creating signature. It is used only when the signature algorithm is RSA.
 * @param[out] ppsignature is a pointer to a newly created signature's. If an error occurs, *ppsignature will be null.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_create_key_pair_rsa()
 * @see ckm_create_key_pair_ecdsa()
 * @see ckm_verify_signature()
 * @see ckm_buffer_free()
 * @see #ckm_hash_algo
 * @see #ckm_rsa_padding_algo
 */
int ckm_create_signature(const char *private_key_alias, const char *password, const ckm_raw_buffer message, const ckm_hash_algo hash, const ckm_rsa_padding_algo padding, ckm_raw_buffer **ppsignature);

/**
 * @brief Verify a given signature on a given message using a public key and returns the signature status.
 *
 * @remarks If password of policy is provided during storing a key, the same password should be provided.
 *
 * @param[in] public_key_alias is the name of public key.
 * @param[in] password is used in decrypting a public key value.
 * @param[in] message is a input on which the signature is created.
 * @param[in] signature is verified with public key.
 * @param[in] hash is the hash algorithm used in verifying signature.
 * @param[in] padding is the RSA padding algorithm used in verifying signature. It is used only when the signature algorithm is RSA.
 *
 * @return 0 on success and the signature is valid, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_VERIFICATION_FAILED the signature is invalid
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_create_key_pair_rsa()
 * @see ckm_create_key_pair_ecdsa()
 * @see ckm_verify_signature()
 * @see #ckm_hash_algo
 * @see #ckm_rsa_padding_algo
 */
int ckm_verify_signature(const char *public_key_alias, const char *password, const ckm_raw_buffer message, const ckm_raw_buffer signature, const ckm_hash_algo hash, const ckm_rsa_padding_algo padding);

/**
 * @brief Verify a certificate chain and return that chain.
 *
 * @remarks The trusted root certificate of the chain should exist in the system's certificate storage.
 * @remarks A newly created ppcert_chain_list should be destroyed by calling ckm_cert_list_all_free() if it is no longer needed.
 *
 * @param[in] cert is the certificate to be verified
 * @param[in] untrustedcerts is the untrusted CA certificates to be used in verifying a certificate chain.
 * @param[out] ppcert_chain_list is a pointer to a newly created certificate chain's handle. If an error occurs, *ppcert_chain_list will be null.
 *
 * @return 0 on success and the signature is valid, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_VERIFICATION_FAILED the certificate chain is not valid
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_INVALID_FORMAT the format of certificate is not valid.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_get_cert_chain_with_alias())
 * @see ckm_cert_list_all_free()
 */
int ckm_get_cert_chain(const ckm_cert *cert, const ckm_cert_list *untrustedcerts, ckm_cert_list **ppcert_chain_list);

/**
 * @brief Verify a certificate chain using a alias list of untrusted certificates and return that chain.
 *
 * @remarks The trusted root certificate of the chain should exist in the system's certificate storage.
 * @remarks A newly created ppcert_chain_list should be destroyed by calling ckm_cert_list_all_free() if it is no longer needed.
 *
 * @param[in] cert is the certificate to be verified
 * @param[in] untrustedcerts is  an alias list of untrusted CA certificates stored in key manager to be used in verifying a certificate chain.
 * @param[out] ppcert_chain_list is a pointer to a newly created certificate chain's handle. If an error occurs, *ppcert_chain_list will be null.
 *
 * @return 0 on success and the signature is valid, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_VERIFICATION_FAILED the certificate chain is not valid
 * @retval #CKM_API_ERROR_INPUT_PARAM input parameter is invalid
 * @retval #CKM_API_ERROR_DB_LOCKED a user key is not loaded in memory(a user is not logged in)
 * @retval #CKM_API_ERROR_DB_ALIAS_UNKNOWN alias doesn't exists.
 * @retval #CKM_API_ERROR_INVALID_FORMAT the format of certificate is not valid.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_get_cert_chain())
 * @see ckm_cert_list_all_free()
 */
int ckm_get_cert_chain_with_alias(const ckm_cert *cert, const ckm_alias_list *untrustedcerts, ckm_cert_list **ppcert_chain_list);


#ifdef __cplusplus
}
#endif

/**
 * @}
 */


#endif /* __TIZEN_CORE_CKMC_MANAGER_H */
