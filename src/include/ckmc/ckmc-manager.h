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
 * @brief       Provides management functions(storing, retrieving, and removing) for keys,
 *              certificates and data of a user and additional crypto functions.
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
 * @remarks Currently only six types of keys are supported for this API. These are RSA
 *          public/private key, DSA public/private key and ECDSA public/private key.
 * @remarks key_type in key may be set to #CKMC_KEY_NONE as an input. key_type is determined inside
 *          key manager during storing keys.
 * @remarks Some private key files are protected by a password. If raw_key in key read from those
 *          encrypted files is encrypted with a password, the password should be provided in the
 *          #ckmc_key_s structure.
 * @remarks If password in policy is provided, the key is additionally encrypted with the password
 *          in policy.
 *
 * @param[in] alias   The name of a key to be stored
 * @param[in] key     The key's binary value to be stored
 * @param[in] policy  The policy about how to store a key securely
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE              Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED         A user key is not loaded in memory (a user is not logged
 *                                       in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS   Alias already exists
 * @retval #CKMC_ERROR_INVALID_FORMAT    The format of raw_key is not valid
 * @retval #CKMC_ERROR_DB_ERROR          Failed due to a database error
 * @retval #CKMC_ERROR_PERMISSION_DENIED Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_remove_key()
 * @see ckmc_get_key()
 * @see ckmc_get_key_alias_list()
 * @see #ckmc_key_s
 * @see #ckmc_policy_s
 */
int ckmc_save_key(const char *alias, const ckmc_key_s key, const ckmc_policy_s policy);

/**
 * @brief Removes a key from key manager.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks To remove key, client must have remove permission to the specified key.
 * @remarks The key owner can remove by default.
 *
 * @param[in] alias The name of a key to be removed
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE              Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED         A user key is not loaded in memory (a user is not logged
 *                                       in)
 * @retval #CKMC_ERROR_DB_ERROR          Failed due to a database error
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN  Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_key()
 * @see ckmc_get_key()
 * @see ckmc_get_key_alias_list()
 */
int ckmc_remove_key(const char *alias);

/**
 * @brief Gets a key from key manager.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks A client can access only data stored by the client.
 * @remarks You must destroy the newly created @a ppkey by calling ckmc_key_free() if it is no
 *          longer needed.
 *
 * @param[in] alias     The name of a key to retrieve
 * @param[in] password  The password used in decrypting a key value \n
 *                      If password of policy is provided in ckmc_save_key(), the same password
 *                      should be provided.
 * @param[out] ppkey    The pointer to a newly created ckmc_key_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE              Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED         A user key is not loaded in memory (a user is not logged
 *                                       in)
 * @retval #CKMC_ERROR_DB_ERROR          Failed due to a database error
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN  Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_key()
 * @see ckmc_remove_key()
 * @see ckmc_get_key_alias_list()
 */
int ckmc_get_key(const char *alias, const char *password, ckmc_key_s **ppkey);

/**
 * @brief Gets all the alias of keys that the client can access.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks A client can access only data stored by the client.
 * @remarks You must destroy the newly created @a ppalias_list by calling ckmc_alias_list_all_free()
 *          if it is no longer needed.
 *
 * @param[out] ppalias_list  The pointer to a newly created ckmc_alias_list_s handle containing all
 *                           available alias of keys \n
 *                           If there is no available key alias, *ppalias_list will be null.
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE              Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED         A user key is not loaded in memory (a user is not logged
 *                                       in)
 * @retval #CKMC_ERROR_DB_ERROR          Failed due to a database error
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN  Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
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
 * @remarks the certificate's binary value will be converted and saved as binary DER encoded
 *          certificates.
 *
 * @param[in] alias  The name of a certificate to be stored
 * @param[in] cert   The certificate's binary value to be stored
 * @param[in] policy The policy about how to store a certificate securely
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS    Alias already exists
 * @retval #CKMC_ERROR_INVALID_FORMAT     The format of raw_cert is not valid
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to a database error
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_remove_cert()
 * @see ckmc_get_cert()
 * @see ckmc_get_cert_alias_list()
 * @see #ckmc_cert_s
 * @see #ckmc_policy_s
 */
int ckmc_save_cert(const char *alias, const ckmc_cert_s cert, const ckmc_policy_s policy);

/**
 * @brief Removes a certificate from key manager.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks To remove certificate, client must have remove permission to the specified certificate.
 * @remarks The key owner can remove by default.
 *
 * @param[in] alias The name of a certificate to be removed
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to a database error
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN   Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_cert()
 * @see ckmc_get_cert()
 * @see ckmc_get_cert_alias_list()
 */
int ckmc_remove_cert(const char *alias);

/**
 * @brief Gets a certificate from key manager.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks A client can access only certificate stored by the client.
 * @remarks A DER encoded certificate will be returned as a return value.
 * @remarks You must destroy the newly created @a ppcert by calling ckmc_cert_free() if it is no
 *          longer needed.
 *
 * @param[in] alias    The name of a certificate to retrieve
 * @param[in] password The password used in decrypting a certificate value \n
 *                     If password of policy is provided in ckmc_save_cert(), the same password
 *                     should be provided.
 * @param[out] ppcert  The pointer to a newly created ckmc_cert_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to a database error
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN   Alias does not exists
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_cert()
 * @see ckmc_remove_cert()
 * @see ckmc_get_cert_alias_list()
 */
int ckmc_get_cert(const char *alias, const char *password, ckmc_cert_s **ppcert);

/**
 * @brief Gets all alias of certificates which the client can access.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks A client can access only data stored by the client.
 * @remarks You must destroy the newly created @a ppalias_list by calling ckmc_alias_list_all_free()
 *          if it is no longer needed.
 *
 * @param[out] ppalias_list The pointer to a newly created ckmc_alias_list_s handle containing all
 *                          available alias of keys \n
 *                          If there is no available key alias, *ppalias_list will be null.
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to a database error
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN   Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_cert()
 * @see ckmc_remove_cert()
 * @see ckmc_get_cert()
 */
int ckmc_get_cert_alias_list(ckmc_alias_list_s** ppalias_list);




/**
 * @brief Stores PKCS12's contents inside key manager based on the provided policies.
 * All items from the PKCS12 will use the same alias.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @param[in] alias         The name of a data to be stored
 * @param[in] pkcs          Pointer to the pkcs12 structure to be saved
 * @param[in] key_policy    The policy about how to store pkcs's private key
 * @param[in] cert_policy   The policy about how to store pkcs's certificate
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS    Alias already exists
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to a database error
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_remove_pkcs12()
 * @see ckmc_get_pkcs12()
 * @see ckmc_get_data_alias_list()
 * @see ckmc_load_from_pkcs12_file2()
 * @see #ckmc_pkcs12_s
 * @see #ckmc_policy_s
 */
int ckmc_save_pkcs12(const char *alias,
                     const ckmc_pkcs12_s *pkcs,
                     const ckmc_policy_s key_policy,
                     const ckmc_policy_s cert_policy);

/**
 * @brief Removes all PKCS12 contents from key manager.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks To remove PKCS12, client must have remove permission to the specified PKCS12 object.
 * @remarks The key owner can remove by default.
 *
 * @param[in] alias The name of PKCS12 to be removed
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to a database error
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN   Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_pkcs12()
 * @see ckmc_get_pkcs12()
 */
int ckmc_remove_pkcs12(const char *alias);

/**
 * @brief Gets a pkcs12 from key manager.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks A client can access only data stored by the client.
 * @remarks You must destroy the newly created @a pkcs12 by calling ckmc_pkcs12_free() if it is no
 *          longer needed.
 *
 * @param[in]  alias        The name of a data to retrieve
 * @param[in]  keyPassword  Password that was used to encrypt privateKey (may be NULL)
 * @param[in]  certPassword Password used to encrypt certificates (may be NULL)
 * @param[out] pkcs12       The pointer to a newly created ckmc_pkcs12_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to a database error
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN   Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 * @retval #CKMC_ERROR_AUTHENTICATION_FAILED
 *                                        keyPassword or certPassword does not match with password
 *                                        used to encrypt data.
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_pkcs12()
 * @see ckmc_remove_pkcs12()
 */
int ckmc_get_pkcs12(const char *alias, const char *keyPassword, const char *certPassword, ckmc_pkcs12_s **pkcs12);

/**
 * @brief Stores a data inside key manager based on the provided policy.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @param[in] alias  The name of a data to be stored
 * @param[in] data   The binary value to be stored
 * @param[in] policy The policy about how to store a data securely
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS    Alias already exists
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to a database error
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_remove_data()
 * @see ckmc_get_data()
 * @see ckmc_get_data_alias_list()
 * @see #ckmc_raw_buffer_s
 * @see #ckmc_policy_s
 */
int ckmc_save_data(const char *alias, ckmc_raw_buffer_s data, const ckmc_policy_s policy);

/**
 * @brief Removes a data from key manager.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks To remove data, client must have remove permission to the specified data object.
 * @remarks The data owner can remove by default.
 *
 * @param[in] alias The name of a data to be removed
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN   Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_data()
 * @see ckmc_get_data()
 * @see ckmc_get_data_alias_list()
 */
int ckmc_remove_data(const char *alias);

/**
 * @brief Gets a data from key manager.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks A client can access only data stored by the client.
 * @remarks You must destroy the newly created @a ppdata by calling ckmc_buffer_free() if it is no
 *          longer needed.
 *
 * @param[in]  alias     The name of a data to retrieve
 * @param[in]  password  The password used in decrypting a data value \n
 *                       If password of policy is provided in ckmc_save_data(), the same password
 *                       should be provided.
 * @param[out] ppdata    The pointer to a newly created ckmc_raw_buffer_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN   Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_data()
 * @see ckmc_remove_data()
 * @see ckmc_get_data_alias_list()
 */
int ckmc_get_data(const char *alias, const char *password, ckmc_raw_buffer_s **ppdata);

/**
 * @brief Gets all alias of data which the client can access.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks A client can access only data stored by the client.
 * @remarks You must destroy the newly created @a ppalias_list by calling ckmc_alias_list_all_free()
 *          if it is no longer needed.
 *
 * @param[out] ppalias_list The pointer to a newly created ckmc_alias_list_s handle containing all
 *                          available alias of keys \n
 *                          If there is no available key alias, *ppalias_list will be null.
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN   Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_data()
 * @see ckmc_remove_data()
 * @see ckmc_get_data()
 */
int ckmc_get_data_alias_list(ckmc_alias_list_s** ppalias_list);




/**
 * @brief Creates RSA private/public key pair and stores them inside key manager based on each
 *        policy.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks If password in policy is provided, the key is additionally encrypted with the password
 *          in policy.
 *
 * @param[in] size                The size of key strength to be created \n
 *                                @c 1024, @c 2048, and @c 4096 are supported.
 * @param[in] private_key_alias   The name of private key to be stored
 * @param[in] public_key_alias    The name of public key to be stored
 * @param[in] policy_private_key  The policy about how to store a private key securely
 * @param[in] policy_public_key   The policy about how to store a public key securely
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS    Alias already exists
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to other DB transaction unexpectedly
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_create_key_pair_dsa()
 * @see ckmc_create_key_pair_ecdsa()
 * @see ckmc_create_signature()
 * @see ckmc_verify_signature()
 */
int ckmc_create_key_pair_rsa(const size_t size,
                             const char *private_key_alias,
                             const char *public_key_alias,
                             const ckmc_policy_s policy_private_key,
                             const ckmc_policy_s policy_public_key);

/**
 * @brief Creates DSA private/public key pair and stores them inside key manager based on each
 *        policy.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks If password in policy is provided, the key is additionally encrypted with the password
 *          in policy.
 *
 * @param[in] size                The size of key strength to be created \n
 *                                @c 1024, @c 2048, @c 3072 and @c 4096 are supported.
 * @param[in] private_key_alias   The name of private key to be stored
 * @param[in] public_key_alias    The name of public key to be stored
 * @param[in] policy_private_key  The policy about how to store a private key securely
 * @param[in] policy_public_key   The policy about how to store a public key securely
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS    Alias already exists
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to other DB transaction unexpectedly
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_create_key_pair_rsa()
 * @see ckmc_create_key_pair_ecdsa()
 * @see ckmc_create_signature()
 * @see ckmc_verify_signature()
 */
int ckmc_create_key_pair_dsa(const size_t size,
                             const char *private_key_alias,
                             const char *public_key_alias,
                             const ckmc_policy_s policy_private_key,
                             const ckmc_policy_s policy_public_key);

/**
 * @brief Creates ECDSA private/public key pair and stores them inside key manager based on each
 *        policy.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks If password in policy is provided, the key is additionally encrypted with the password
 *          in policy.
 *
 * @param[in] type                The type of elliptic curve of ECDSA
 * @param[in] private_key_alias   The name of private key to be stored
 * @param[in] public_key_alias    The name of public key to be stored
 * @param[in] policy_private_key  The policy about how to store a private key securely
 * @param[in] policy_public_key   The policy about how to store a public key securely
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ALIAS_EXISTS    Alias already exists
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to other DB transaction unexpectedly
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_create_key_pair_rsa()
 * @see ckmc_create_key_pair_dsa()
 * @see ckmc_create_signature()
 * @see ckmc_verify_signature()
 * @see #ckmc_ec_type_e
 */
int ckmc_create_key_pair_ecdsa(const ckmc_ec_type_e type,
                               const char *private_key_alias,
                               const char *public_key_alias,
                               const ckmc_policy_s policy_private_key,
                               const ckmc_policy_s policy_public_key);

/**
 * @brief Creates a signature on a given message using a private key and returns the signature.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks If password of policy is provided during storing a key, the same password should be
 *          provided.
 * @remarks You must destroy the newly created @a ppsignature by calling ckmc_buffer_free() if it is
 *          no longer needed.
 *
 * @param[in]  private_key_alias  The name of private key
 * @param[in]  password           The password used in decrypting a private key value
 * @param[in]  message            The message that is signed with a private key
 * @param[in]  hash               The hash algorithm used in creating signature
 * @param[in]  padding            The RSA padding algorithm used in creating signature \n
 *                                It is used only when the signature algorithm is RSA.
 * @param[out] ppsignature        The pointer to a newly created signature \n
 *                                If an error occurs, @a *ppsignature will be null.
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED          A user key is not loaded in memory (a user is not logged
 *                                        in)
 * @retval #CKMC_ERROR_DB_ERROR           Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN   Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_create_key_pair_rsa()
 * @see ckmc_create_key_pair_ecdsa()
 * @see ckmc_verify_signature()
 * @see ckmc_buffer_free()
 * @see #ckmc_hash_algo_e
 * @see #ckmc_rsa_padding_algo_e
 */
int ckmc_create_signature(const char *private_key_alias,
                          const char *password,
                          const ckmc_raw_buffer_s message,
                          const ckmc_hash_algo_e hash,
                          const ckmc_rsa_padding_algo_e padding,
                          ckmc_raw_buffer_s **ppsignature);

/**
 * @brief Verifies a given signature on a given message using a public key and returns the signature
 *        status.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks If password of policy is provided during storing a key, the same password should be
 *          provided.
 *
 * @param[in] public_key_alias  The name of public key
 * @param[in] password          The password used in decrypting a public key value
 * @param[in] message           The input on which the signature is created
 * @param[in] signature         The signature that is verified with public key
 * @param[in] hash              The hash algorithm used in verifying signature
 * @param[in] padding           The RSA padding algorithm used in verifying signature \n
 *                              It is used only when the signature algorithm is RSA.
 *
 * @return @c 0 on success and the signature is valid,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_VERIFICATION_FAILED  The signature is invalid
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED            A user key is not loaded in memory (a user is not logged
 *                                          in)
 * @retval #CKMC_ERROR_DB_ERROR             Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN     Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED    Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_create_key_pair_rsa()
 * @see ckmc_create_key_pair_ecdsa()
 * @see ckmc_verify_signature()
 * @see #ckmc_hash_algo_e
 * @see #ckmc_rsa_padding_algo_e
 */
int ckmc_verify_signature(const char *public_key_alias,
                          const char *password,
                          const ckmc_raw_buffer_s message,
                          const ckmc_raw_buffer_s signature,
                          const ckmc_hash_algo_e hash,
                          const ckmc_rsa_padding_algo_e padding);

/**
 * @deprecated, see ckmc_get_certificate_chain()
 * @brief Verifies a certificate chain and returns that chain.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks The trusted root certificate of the chain should exist in the system's certificate
 *          storage.
 * @remarks You must destroy the newly created @a ppcert_chain_list by calling
 *          ckmc_cert_list_all_free() if it is no longer needed.
 *
 * @param[in] cert               The certificate to be verified
 * @param[in] untrustedcerts     The untrusted CA certificates to be used in verifying a certificate
 *                               chain
 * @param[out] ppcert_chain_list The pointer to a newly created certificate chain's handle \n
 *                               If an error occurs, @a *ppcert_chain_list will be null.
 *
 * @return @c 0 on success and the signature is valid,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_VERIFICATION_FAILED  The certificate chain is not valid
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED            A user key is not loaded in memory (a user is not logged
 *                                          in)
 * @retval #CKMC_ERROR_DB_ERROR             Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_INVALID_FORMAT       The format of certificate is not valid
 * @retval #CKMC_ERROR_PERMISSION_DENIED    Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_get_cert_chain_with_alias())
 * @see ckmc_cert_list_all_free()
 */
int ckmc_get_cert_chain(const ckmc_cert_s *cert,
                        const ckmc_cert_list_s *untrustedcerts,
                        ckmc_cert_list_s **ppcert_chain_list);

/**
 * @deprecated, see ckmc_get_certificate_chain_with_alias()
 * @brief Verifies a certificate chain using an alias list of untrusted certificates and return that
 *        chain.
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks The trusted root certificate of the chain should exist in the system's certificate
 *          storage.
 * @remarks You must destroy the newly created @a ppcert_chain_list by calling
 *          ckmc_cert_list_all_free() if it is no longer needed.
 *
 * @param[in] cert               The certificate to be verified
 * @param[in] untrustedcerts     The alias list of untrusted CA certificates stored in key manager
 *                               to be used in verifying a certificate chain
 * @param[out] ppcert_chain_list The pointer to a newly created certificate chain's handle \n
 *                               If an error occurs, @a *ppcert_chain_list will be null.
 *
 * @return @c 0 on success and the signature is valid,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_VERIFICATION_FAILED  The certificate chain is not valid
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED            A user key is not loaded in memory (a user is not logged
 *                                          in)
 * @retval #CKMC_ERROR_DB_ERROR             Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN     Alias does not exist
 * @retval #CKMC_ERROR_INVALID_FORMAT       The format of certificate is not valid
 * @retval #CKMC_ERROR_PERMISSION_DENIED    Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_get_cert_chain())
 * @see ckmc_cert_list_all_free()
 */
int ckmc_get_cert_chain_with_alias(const ckmc_cert_s *cert,
                                   const ckmc_alias_list_s *untrustedcerts,
                                   ckmc_cert_list_s **ppcert_chain_list);

/**
 * @brief Verifies a certificate chain and returns that chain using user entered trusted and
 *        untrusted CA certificates
 *
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks If the trusted root certificates are provided as a user input, these certificates do not
 *          need to exist in the system's certificate storage.
 * @remarks You must destroy the newly created @a ppcert_chain_list by calling
 *          ckmc_cert_list_all_free() if it is no longer needed.
 *  *
 * @param[in] cert                    The certificate to be verified
 * @param[in] untrustedcerts          The untrusted CA certificates to be used in verifying a
 *                                    certificate chain
 * @param[in] trustedcerts            The trusted CA certificates to be used in verifying a
 *                                    certificate chain
 * @param[in] use_trustedsystemcerts  The flag indicating the use of the trusted root certificates
 *                                    in the system's certificate storage.
 * @param[out] ppcert_chain_list The pointer to a newly created certificate chain's handle \n
 *                               If an error occurs, @a *ppcert_chain_list will be null.
 *
 * @return @c 0 on success and the signature is valid,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_VERIFICATION_FAILED  The certificate chain is not valid
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED            A user key is not loaded in memory (a user is not logged
 *                                          in)
 * @retval #CKMC_ERROR_DB_ERROR             Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_INVALID_FORMAT       The format of certificate is not valid
 * @retval #CKMC_ERROR_PERMISSION_DENIED    Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_get_cert_chain_with_alias())
 * @see ckmc_cert_list_all_free()
 */
int ckmc_get_certificate_chain(const ckmc_cert_s *cert,
                               const ckmc_cert_list_s *untrustedcerts,
                               const ckmc_cert_list_s *trustedcerts,
                               const bool use_trustedsystemcerts,
                               ckmc_cert_list_s **ppcert_chain_list);

/**
 * @brief Verifies a certificate chain and returns that chain using alias lists of untrusted and
 *        trusted certificates
 *
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks If the alias list of trusted root certificates is provided as a user input, these
 *          certificates do not need to exist in the system's certificate storage.
 * @remarks You must destroy the newly created @a ppcert_chain_list by calling
 *          ckmc_cert_list_all_free() if it is no longer needed.
 *
 * @param[in] cert                    The certificate to be verified
 * @param[in] untrustedcerts          The alias list of untrusted CA certificates stored in key
 *                                    manager to be used in verifying a certificate chain
 * @param[in] trustedcerts            The alias list of trusted CA certificates stored in key
 *                                    manager to be used in verifying a certificate chain
 * @param[in] use_trustedsystemcerts  The flag indicating the use of the trusted root certificates
 *                                    in the system's certificate storage.
 * @param[out] ppcert_chain_list The pointer to a newly created certificate chain's handle \n
 *                               If an error occurs, @a *ppcert_chain_list will be null.
 *
 * @return @c 0 on success and the signature is valid,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_VERIFICATION_FAILED  The certificate chain is not valid
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED            A user key is not loaded in memory (a user is not logged
 *                                          in)
 * @retval #CKMC_ERROR_DB_ERROR             Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN     Alias does not exist
 * @retval #CKMC_ERROR_INVALID_FORMAT       The format of certificate is not valid
 * @retval #CKMC_ERROR_PERMISSION_DENIED    Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_get_cert_chain())
 * @see ckmc_cert_list_all_free()
 */
int ckmc_get_certificate_chain_with_alias(const ckmc_cert_s *cert,
                                          const ckmc_alias_list_s *untrustedcerts,
                                          const ckmc_alias_list_s *trustedcerts,
                                          const bool use_trustedsystemcerts,
                                          ckmc_cert_list_s **ppcert_chain_list);

/**
 * @brief Perform OCSP which checks certificate is whether revoked or not
 *
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @param[in] pcert_chain_list   Valid certificate chain to perform OCSP check
 * @param[out] ocsp_status       The pointer to status result of OCSP check
 *
 * @return @c 0 on success, otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 * @retval #CKMC_ERROR_PERMISSION_DENIED    Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 * @pre @a pcert_chain_list is created with ckmc_get_certificate_chain() or
 *      ckmc_get_certificate_chain_with_alias()
 *
 * @see ckmc_get_cert_chain())
 * @see ckmc_cert_list_all_free()
 */
int ckmc_ocsp_check(const ckmc_cert_list_s *pcert_chain_list, ckmc_ocsp_status_e *ocsp_status);

/**
 * @deprecated, see ckmc_set_permission()
 * @brief Allows another application to access client's application data
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks Data identified by @a alias should exist
 *
 * @param[in] alias       Data alias for which access will be granted
 * @param[in] accessor    Package id of the application that will gain access rights
 * @param[in] granted     Rights granted for @a accessor application
 *
 * @return @c 0 on success, otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED            A user key is not loaded in memory (a user is not logged
 *                                          in)
 * @retval #CKMC_ERROR_DB_ERROR             Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN     Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED    Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_deny_access()
 */
int ckmc_allow_access(const char *alias, const char *accessor, ckmc_access_right_e granted);

/**
 * @brief Allows another application to access client's application data
 *
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks Data identified by @a alias should exist
 *
 * @param[in] alias       Data alias for which access will be granted
 * @param[in] accessor    Package id of the application that will gain access rights
 * @param[in] permissions Mask of permissions granted for @a accessor application
 *                        (@a ckmc_permission_e)
 *                        (previous permission mask will be replaced with the new mask value)
 *
 * @return @c 0 on success, otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED            A user key is not loaded in memory (a user is not logged
 *                                          in)
 * @retval #CKMC_ERROR_DB_ERROR             Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN     Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED    Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 */
int ckmc_set_permission(const char *alias, const char *accessor, int permissions);

/**
 * @deprecated, see ckmc_set_permission()
 * @brief Revokes another application's access to client's application data
 *
 * @since_tizen 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks Data identified by @a alias should exist
 * @remarks Only access previously granted with ckmc_allow_access can be revoked.
 *
 * @param[in] alias       Data alias for which access will be revoked
 * @param[in] accessor    Package id of the application that will lose access rights
 *
 * @return @c 0 on success, otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid or the @a accessor doesn't
 *                                          have access to @a alias
 * @retval #CKMC_ERROR_DB_LOCKED            A user key is not loaded in memory (a user is not logged
 *                                          in)
 * @retval #CKMC_ERROR_DB_ERROR             Failed due to the error with unknown reason
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN     Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED    Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_allow_access()
 * @see ckmc_set_permission()
 */
int ckmc_deny_access(const char *alias, const char *accessor);

/**
 * @brief Removes a an entry (no matter of type) from the key manager.
 *
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager
 *
 * @remarks To remove item, client must have remove permission to the specified item.
 * @remarks The item owner can remove by default.
 *
 * @param[in] alias Item alias to be removed
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE              Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER Input parameter is invalid
 * @retval #CKMC_ERROR_DB_LOCKED         A user key is not loaded in memory (a user is not logged
 *                                       in)
 * @retval #CKMC_ERROR_DB_ERROR          Failed due to a database error
 * @retval #CKMC_ERROR_DB_ALIAS_UNKNOWN  Alias does not exist
 * @retval #CKMC_ERROR_PERMISSION_DENIED Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_save_key()
 * @see ckmc_save_cert
 * @see ckmc_save_data
 * @see ckmc_save_pkcs12
 * @see ckmc_create_key_pair_rsa
 * @see ckmc_create_key_pair_dsa
 * @see ckmc_create_key_pair_ecdsa
 */
int ckmc_remove_alias(const char *alias);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */


#endif /* __TIZEN_CORE_CKMC_MANAGER_H */
