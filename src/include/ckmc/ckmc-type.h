/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @version     1.0
 * @brief       Definitions of struct for the Key Manager's CAPI and their utility functions.
 */

#ifndef __TIZEN_CORE_CKMC_TYPE_H
#define __TIZEN_CORE_CKMC_TYPE_H

#include <stddef.h>
#include <stdint.h>
#include <ckmc/ckmc-error.h>

#define KEY_MANAGER_CAPI __attribute__((visibility("default")))


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_KEY_MANAGER_TYPES_MODULE
 * @{
 */

/**
 * @brief Separator between alias and label.
 * @since_tizen 2.3
 * @remarks Alias can be provided as an alias alone, or together with label - in this
 *          case, separator " " (space bar) is used to separate label and alias.
 *
 * @see key-manager_doc.h
 */
KEY_MANAGER_CAPI extern char const * const ckmc_label_name_separator;

/**
 * @brief Shared owner label
 * @since_tizen 3.0
 * @remarks Shared database label - user may be given permission to access shared
 *          database items. In such case, the alias should contain shared database
 *          label.
 *
 * @see #ckmc_label_name_separator
 * @see key-manager_doc.h
 */
KEY_MANAGER_CAPI extern char const * const ckmc_label_shared_owner;

/**
 * @brief Enumeration for key types of key manager.
 * @since_tizen 2.3
 */
typedef enum __ckmc_key_type {
    CKMC_KEY_NONE = 0,       /**< Key type not specified */
    CKMC_KEY_RSA_PUBLIC,     /**< RSA public key */
    CKMC_KEY_RSA_PRIVATE,    /**< RSA private key */
    CKMC_KEY_ECDSA_PUBLIC,   /**< ECDSA public key */
    CKMC_KEY_ECDSA_PRIVATE,  /**< ECDSA private key */
    CKMC_KEY_DSA_PUBLIC,     /**< DSA public key */
    CKMC_KEY_DSA_PRIVATE,    /**< DSA private key */
    CKMC_KEY_AES,            /**< AES key */
} ckmc_key_type_e;

/**
 * @brief Enumeration for data format.
 * @since_tizen 2.3
 */
typedef enum __ckmc_data_format {
    CKMC_FORM_DER_BASE64 = 0,  /**< DER format base64 encoded data */
    CKMC_FORM_DER,             /**< DER encoded data */
    CKMC_FORM_PEM              /**< PEM encoded data. It consists of the DER format base64 encoded
                                    with additional header and footer lines. */
} ckmc_data_format_e;

/**
 * @brief Enumeration for elliptic curve.
 * @since_tizen 2.3
 */
typedef enum __ckmc_ec_type {
    CKMC_EC_PRIME192V1 = 0, /**< Elliptic curve domain "secp192r1" listed in "SEC 2" recommended
                                 elliptic curve domain  */
    CKMC_EC_PRIME256V1,     /**< "SEC 2" recommended elliptic curve domain - secp256r1 */
    CKMC_EC_SECP384R1       /**< NIST curve P-384 (covers "secp384r1", the elliptic curve domain
                                 listed in See SEC 2 */
} ckmc_ec_type_e;

/**
 * @brief Enumeration for hash algorithm.
 * @since_tizen 2.3
 */
typedef enum __ckmc_hash_algo {
    CKMC_HASH_NONE = 0, /**< No Hash Algorithm  */
    CKMC_HASH_SHA1,     /**< Hash Algorithm SHA1  */
    CKMC_HASH_SHA256,   /**< Hash Algorithm SHA256  */
    CKMC_HASH_SHA384,   /**< Hash Algorithm SHA384  */
    CKMC_HASH_SHA512    /**< Hash Algorithm SHA512  */
} ckmc_hash_algo_e;

/**
 * @brief Enumeration for RSA padding algorithm.
 * @since_tizen 2.3
 */
typedef enum __ckmc_rsa_padding_algo {
    CKMC_NONE_PADDING = 0,  /**< No Padding */
    CKMC_PKCS1_PADDING,     /**< PKCS#1 Padding */
    CKMC_X931_PADDING       /**< X9.31 padding */
} ckmc_rsa_padding_algo_e;

/**
 * @deprecated Deprecated since 2.4. [Use ckmc_permission_e() instead]
 * @brief Enumeration for database access rights.
 * @since_tizen 2.3
 */
typedef enum __ckmc_access_right{
    CKMC_AR_READ = 0,       /**< Access right for read*/
    CKMC_AR_READ_REMOVE     /**< Access right for read and remove*/
} ckmc_access_right_e;

/**
 * @brief Enumeration for permissions to access/modify alias.
 * @since_tizen 2.4
 */
typedef enum __ckmc_permission{
    CKMC_PERMISSION_NONE        = 0x00, /**< Clear permissions */
    CKMC_PERMISSION_READ        = 0x01, /**< Eead allowed */
    CKMC_PERMISSION_REMOVE      = 0x02  /**< Remove allowed */
} ckmc_permission_e;

/**
 * @brief The structure for binary buffer used in key manager CAPI.
 * @since_tizen 2.3
 */
typedef struct __ckmc_raw_buff {
    unsigned char* data; /**< Byte array containing binary data */
    size_t size;         /**< The size of the binary data */
} ckmc_raw_buffer_s;

/**
 * @brief The structure for a policy for storing key/certificate/binary data.
 * @since_tizen 2.3
 */
typedef struct __ckmc_policy {
    char* password;   /**< Byte array used to encrypt data inside CKM. If it is not null, the data
                           (or key, or certificate) is stored encrypted with this password inside
                           key manager */
    bool extractable; /**< If true key may be extracted from storage */
} ckmc_policy_s;

/**
 * @brief The structure for key used in key manager CAPI.
 * @since_tizen 2.3
 */
typedef struct __ckmc_key {
    unsigned char* raw_key;   /**< Byte array of key. raw_key may be encrypted with password */
    size_t key_size;          /**< The byte size of raw_key */
    ckmc_key_type_e key_type; /**< The raw_key's type */
    char* password;           /**< Byte array used to decrypt data raw_key inside key manager. */
} ckmc_key_s;

/**
 * @brief The structure for certificate used in key manager CAPI.
 * @since_tizen 2.3
 */
typedef struct __ckmc_cert {
    unsigned char* raw_cert;  /**< Byte array of certificate */
    size_t cert_size;         /**< Byte size of raw_cert */
    ckmc_data_format_e data_format; /**< Raw_cert's encoding format */
} ckmc_cert_s;

/**
 * @brief The structure for linked list of alias.
 * @since_tizen 2.3
 */
typedef struct __ckmc_alias_list {
    char *alias;                    /**< The name of key, certificate or data stored in key manager */
    struct __ckmc_alias_list *next; /**< The pointer pointing to the next ckmc_alias_list_s */
} ckmc_alias_list_s;

/**
 * @brief The structure for linked list of ckmc_cert_s
 * @since_tizen 2.3
 */
typedef struct __ckmc_cert_list {
    ckmc_cert_s *cert;             /**< The pointer of ckmc_cert_s */
    struct __ckmc_cert_list *next; /**< The pointer pointing to the next ckmc_cert_list_s */
} ckmc_cert_list_s;

/**
 * @brief Enumeration for OCSP status.
 * @since_tizen 2.4
 */
typedef enum __ckmc_ocsp_status {
    CKMC_OCSP_STATUS_GOOD = 0,          /**< OCSP status is good */
    CKMC_OCSP_STATUS_REVOKED,           /**< The certificate is revoked */
    CKMC_OCSP_STATUS_UNKNOWN,           /**< Unknown error */
    CKMC_OCSP_ERROR_UNSUPPORTED,        /**< The certificate does not provide OCSP extension */
    CKMC_OCSP_ERROR_INVALID_URL,        /**< The invalid URL in certificate OCSP extension */
    CKMC_OCSP_ERROR_INVALID_RESPONSE,   /**< The invalid response from OCSP server */
    CKMC_OCSP_ERROR_REMOTE,             /**< OCSP remote server error */
    CKMC_OCSP_ERROR_NET,                /**< Network connection error */
    CKMC_OCSP_ERROR_INTERNAL            /**< OpenSSL API error */
} ckmc_ocsp_status_e;

/**
 * @brief The structure for PKCS12 used in key manager CAPI.
 * @since_tizen 2.4
 */
typedef struct __ckmc_pkcs12 {
    ckmc_key_s  *priv_key;      /**< The private key, may be null */
    ckmc_cert_s *cert;          /**< The certificate, may be null */
    ckmc_cert_list_s *ca_chain; /**< The chain certificate list, may be null */
} ckmc_pkcs12_s;

/**
 * @brief Enumeration for crypto algorithm parameters.
 * @since_tizen 3.0
 *
 * @see #ckmc_algo_type_e
 */
typedef enum __ckmc_param_name {
    CKMC_PARAM_ALGO_TYPE = 1,

    CKMC_PARAM_ED_IV = 101,         /**< 16B buffer (up to 2^64-1 bytes long in case of AES GCM) */
    CKMC_PARAM_ED_CTR_LEN,          /**< integer - ctr length in bits*/
    CKMC_PARAM_ED_AAD,              /**< buffer */
    CKMC_PARAM_ED_TAG_LEN,          /**< integer - tag length in bits */
    CKMC_PARAM_ED_LABEL,            /**< buffer */

    CKMC_PARAM_GEN_KEY_LEN = 201,   /**< integer - key length in bits */
    CKMC_PARAM_GEN_EC,              /**< integer - elliptic curve (ckmc_ec_type_e) */

    CKMC_PARAM_SV_HASH_ALGO = 301,  /**< integer - hash algorithm (ckmc_hash_algo_e) */
    CKMC_PARAM_SV_RSA_PADDING       /**< integer - RSA padding (ckmc_rsa_padding_algo_e) */
} ckmc_param_name_e;

/**
 * @brief Structure for algorithm parameter list.
 * @since_tizen 3.0
 */
typedef struct __ckmc_param_list ckmc_param_list_s;

/**
 * @brief Enumeration for crypto algorithm types.
 * @since_tizen 3.0
 *
 * @see #ckmc_param_name_e
 */
typedef enum __ckmc_algo_type {
    CKMC_ALGO_AES_CTR = 1,   /**< AES-CTR algorithm
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_ED_IV
                                  - CKMC_PARAM_ED_CTR_LEN (128 only) */

    CKMC_ALGO_AES_CBC,       /**< AES-CBC algorithm
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_ED_IV */

    CKMC_ALGO_AES_GCM,       /**< AES-GCM algorithm
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_ED_IV
                                  - CKMC_PARAM_ED_TAG_LEN
                                  - CKMC_PARAM_ED_AAD */

    CKMC_ALGO_AES_CFB,       /**< AES-CFB algorithm
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_ED_IV */

    CKMC_ALGO_RSA_OAEP,      /**< RSA-OAEP algorithm
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_ED_LABEL */

    CKMC_ALGO_RSA_SV,        /**< RSA algorithm used for signing/verification
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_SV_HASH_ALGO
                                  - CKMC_PARAM_SV_RSA_PADDING */

    CKMC_ALGO_DSA_SV,        /**< DSA algorithm used for signing/verification
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_SV_HASH_ALGO */

    CKMC_ALGO_ECDSA_SV,      /**< ECDA algorithm used for signing/verification
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_SV_HASH_ALGO */

    CKMC_ALGO_RSA_GEN,       /**< RSA algorithm used for key generation
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_GEN_KEY_LEN */

    CKMC_ALGO_DSA_GEN,       /**< DSA algorithm used for key generation
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_GEN_KEY_LEN */

    CKMC_ALGO_ECDSA_GEN,     /**< ECDSA algorithm used for key generation
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_GEN_EC */

    CKMC_ALGO_AES_GEN,       /**< AES key generation
                                  Supported parameters:
                                  - CKMC_PARAM_ALGO_TYPE,
                                  - CKMC_PARAM_GEN_KEY_LEN */
} ckmc_algo_type_e;

/**
 * @brief Creates a new @a ckmc_key_s handle and returns it.
 *
 * @since_tizen 2.4
 *
 * @remarks You must destroy the newly created @a ckmc_key_s by calling ckmc_key_free() if it is no
 *          longer needed.
 *
 * @param[in] raw_key  The byte array of key \n
 *                     @a raw_key may be encrypted with password
 * @param[in] key_size The byte size of @a raw_key
 * @param[in] key_type The @a raw_key's type
 * @param[in] password The byte array used to decrypt @a raw_key inside key manager \n
 *                     If @a raw_key is not encrypted, @a password can be null
 * @param[out] ppkey   The pointer to a newly created @a ckmc_key_s handle
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE              Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY     Not enough memory
 *
 * @see ckmc_key_free()
 * @see #ckmc_key_s
 */
int ckmc_key_new(unsigned char *raw_key,
                 size_t key_size,
                 ckmc_key_type_e key_type,
                 char *password, ckmc_key_s **ppkey);

/**
 * @brief Destroys the @a ckmc_key_s handle and releases all its resources.
 *
 * @since_tizen 2.3
 *
 * @param[in] key The @a ckmc_key_s handle to destroy
 *
 */
void ckmc_key_free(ckmc_key_s *key);

/**
 * @brief Creates a new @a ckmc_raw_buffer_s handle and returns it.
 *
 * @since_tizen 2.4
 *
 * @remarks You must destroy the newly created @a ckmc_raw_buffer_s by calling ckmc_buffer_free() if
 *          it is no longer needed.
 *
 * @param[in]  data      The byte array of buffer
 * @param[in]  size      The byte size of buffer
 * @param[out] ppbuffer  The pointer to a newly created @a ckmc_buffer_s handle
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_buffer_free()
 * @see #ckmc_raw_buffer_s
 */
int ckmc_buffer_new(unsigned char *data, size_t size, ckmc_raw_buffer_s **ppbuffer);

/**
 * @brief Destroys the @a ckmc_raw_buffer_s handle and releases all its resources.
 *
 * @since_tizen 2.3
 *
 * @param[in] buffer The @a ckmc_raw_buffer_s structure to destroy
 *
 */
void ckmc_buffer_free(ckmc_raw_buffer_s *buffer);

/**
 * @brief Creates a new @a ckmc_cert_s handle and returns it.
 *
 * @since_tizen 2.4
 *
 * @remarks You must destroy the newly created @a ckmc_cert_s by calling ckmc_cert_free() if it is
 *          no longer needed.
 *
 * @param[in]  raw_cert     The byte array of certificate
 * @param[in]  cert_size    The byte size of raw_cert
 * @param[in]  data_format  The encoding format of raw_cert
 * @param[out] ppcert       The pointer to a newly created @a ckmc_cert_s handle
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_cert_free()
 * @see ckmc_load_cert_from_file()
 * @see #ckmc_cert_s
 */
int ckmc_cert_new(unsigned char *raw_cert,
                  size_t cert_size,
                  ckmc_data_format_e data_format,
                  ckmc_cert_s **ppcert);

/**
 * @brief Destroys the @a ckmc_cert handle and releases all its resources.
 *
 * @since_tizen 2.3
 *
 * @param[in] cert The @a ckmc_cert_s handle to destroy
 *
 * @see ckmc_load_cert_from_file()
 * @see ckmc_load_from_pkcs12_file
 */
void ckmc_cert_free(ckmc_cert_s *cert);

/**
 * @brief Creates a new @a ckmc_cert_s handle from a given file and returns it.
 *
 * @since_tizen 2.3
 *
 * @remarks You must destroy the newly created @a ckmc_cert_s by calling ckmc_cert_free() if it is
 *          no longer needed.
 *
 * @param[in]  file_path  The path of certificate file to be loaded \n
 *                        The only DER or PEM encoded certificate file is supported
 * @param[out] cert       The pointer of newly created @a ckmc_cert_s handle
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                Successful
 * @retval #CKMC_ERROR_OUT_OF_MEMORY       Not enough memory space
 * @retval #CKMC_ERROR_INVALID_FORMAT      Invalid certificate file format
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED  Provided file does not exist or cannot be accessed
 *
 * @see ckmc_cert_free()
 * @see #ckmc_cert_s
 */
int ckmc_load_cert_from_file(const char *file_path, ckmc_cert_s **cert);

/**
 * @brief Creates a new @a ckmc_pkcs12_s handle and returns it.
 *
 * @since_tizen 2.4
 *
 * @remarks You must destroy the newly created @a ckmc_pkcs12_s by calling ckmc_pkcs12_free() if it
 *          is no longer needed.
 * @remarks On success, private_key, cert && ca_cert_list ownership is transferred into newly
 *          returned ckmc_pkcs12_s.
 *
 * @param[in]  private_key      @a ckmc_key_s handle to the private key (optional)
 * @param[in]  cert             @a ckmc_cert_s handle to the certificate (optional)
 * @param[in]  ca_cert_list     @a ckmc_cert_list_s list of chain certificate handles (optional)
 * @param[out] pkcs12_bundle    The pointer to a newly created @a ckmc_pkcs12_s handle
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid or private_key, cert and
 *                                        ca_cert_list all are null
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_pkcs12_free()
 * @see ckmc_load_from_pkcs12_file()
 * @see ckmc_pkcs12_load()
 * @see #ckmc_key_s
 * @see #ckmc_cert_s
 * @see #ckmc_cert_list_s
 * @see #ckmc_pkcs12_s
 */
int ckmc_pkcs12_new(ckmc_key_s *private_key,
                    ckmc_cert_s *cert,
                    ckmc_cert_list_s *ca_cert_list,
                    ckmc_pkcs12_s **pkcs12_bundle);

/**
 * @deprecated Deprecated since 2.4. [Use ckmc_pkcs12_load() instead]
 * @brief Creates a new @a ckmc_key_s(private key), @a ckmc_cert_s(certificate), and
 *        @a ckmc_cert_list_s(CA certificates) handle from a given PKCS#12 file and returns them.
 *
 * @since_tizen 2.3
 *
 * @remarks You must destroy the newly created @a ckmc_key_s, @a ckmc_cert_s, and
 *          @a ckmc_cert_list_s by calling ckmc_key_free(), ckmc_cert_free(), and
 *          ckmc_cert_list_all_free() if they are no longer needed.
 *
 * @param[in]  file_path    The path of PKCS12 file to be loaded
 * @param[in]  passphrase   The passphrase used to decrypt the PCKS12 file \n
 *                          If PKCS12 file is not encrypted, passphrase can be null
 * @param[out] private_key  The pointer of newly created @a ckmc_key_s handle for a private key
 * @param[out] cert         The pointer of newly created @a ckmc_cert_s handle for a certificate \n
 *                          It is null if the PKCS12 file does not contain a certificate
 * @param[out] ca_cert_list The pointer of newly created @a ckmc_cert_list_s handle for CA
 *                          certificates \n
 *                          It is null if the PKCS12 file does not contain CA certificates
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                Successful
 * @retval #CKMC_ERROR_OUT_OF_MEMORY       Not enough memory space
 * @retval #CKMC_ERROR_INVALID_FORMAT      Invalid PKCS12 file format
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED  Provided file does not exist or cannot be accessed
 *
 * @see ckmc_pkcs12_new()
 * @see ckmc_pkcs12_load()
 * @see ckmc_key_free()
 * @see ckmc_cert_free()
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_key_s
 * @see #ckmc_cert_s
 * @see #ckmc_cert_list_s
 */
int ckmc_load_from_pkcs12_file(const char *file_path,
                               const char *passphrase,
                               ckmc_key_s **private_key, ckmc_cert_s **cert,
                               ckmc_cert_list_s **ca_cert_list);

/**
 * @brief Creates a new @a ckmc_pkcs12_s handle from a given PKCS#12 file and returns it.
 *
 * @since_tizen 2.4
 *
 * @remarks You must destroy the newly created @a ckmc_pkcs12_s by calling ckmc_pkcs12_free() if
 *          they are no longer needed.
 *
 * @param[in]  file_path    The path of PKCS12 file to be loaded
 * @param[in]  passphrase   The passphrase used to decrypt the PCKS12 file \n
 *                          If PKCS12 file is not encrypted, passphrase can be null
 * @param[out] ca_cert_list The pointer of newly created @a ckmc_cert_list_s handle for CA
 *                          certificates \n
 *                          It is null if the PKCS12 file does not contain CA certificates
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                Successful
 * @retval #CKMC_ERROR_OUT_OF_MEMORY       Not enough memory space
 * @retval #CKMC_ERROR_INVALID_FORMAT      Invalid PKCS12 file format
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED  Provided file does not exist or cannot be accessed
 *
 * @see ckmc_pkcs12_free()
 * @see #ckmc_pkcs12_s
 */
int ckmc_pkcs12_load(const char *file_path,
                                const char *passphrase,
                                ckmc_pkcs12_s **pkcs12_bundle);

/**
 * @brief Destroys the @a ckmc_pkcs12_s handle and releases all its resources.
 *
 * @since_tizen 2.4
 *
 * @param[in] pkcs12 The @a ckmc_pkcs12_s handle to destroy
 *
 * @see ckmc_pkcs12_new()
 * @see ckmc_pkcs12_load()
 */
void ckmc_pkcs12_free(ckmc_pkcs12_s *pkcs12);

/**
 * @brief Creates a new @a ckmc_alias_list_s handle and returns it.
 *        The alias pointer in the returned @a ckmc_alias_list_s handle points to the provided
 *        characters and next is null.
 *
 * @since_tizen 2.4
 *
 * @remarks You must destroy the newly created @a ckmc_alias_list_s
 *          by calling ckmc_alias_list_free() or ckmc_alias_list_all_free() if it is no longer
 *          needed.
 *
 * @param[in]  alias        The first item to be set in the newly created @a ckmc_alias_list_s
 * @param[out] ppalias_list The pointer to a newly created @a ckmc_alias_list_s handle
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE              Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY     Not enough memory
 *
 * @see ckmc_alias_list_all_free()
 * @see #ckmc_alias_list_s
 */
int ckmc_alias_list_new(char *alias, ckmc_alias_list_s **ppalias_list);

/**
 * @brief Creates a new @a ckmc_alias_list_s handle, adds it to a previous @a ckmc_alias_list_s and
 *        returns it. The alias pointer in the returned @a ckmc_alias_list_s handle points to the
 *        provided characters and next is null.
 *
 * @since_tizen 2.4
 *
 * @param[in]  previous  The last @a ckmc_alias_list_s handle to which a newly created
 *                       @a ckmc_alias_list_s is added
 * @param[in]  alias     The item to be set in the newly created @a ckmc_alias_list_s
 * @param[out] pplast    The pointer to a newly created and added @a ckmc_alias_list_s handle
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_alias_list_all_free()
 * @see #ckmc_alias_list_s
 */
int ckmc_alias_list_add(ckmc_alias_list_s *previous,
                        char *alias,
                        ckmc_alias_list_s **pplast);

/**
 * @brief Destroys the @a ckmc_alias_list_s handle and releases resources of @a ckmc_alias_list_s
 *        from the provided first handle cascadingly.
 *
 * @since_tizen 2.4
 *
 * @remarks It does not destroy an alias itself in @a ckmc_alias_list_s.
 *
 * @param[in] first The first @a ckmc_alias_list_s handle to destroy
 *
 * @see ckmc_alias_list_all_free()
 * @see #ckmc_alias_list_s
 */
void ckmc_alias_list_free(ckmc_alias_list_s *first);

/**
 * @brief Destroys the @a ckmc_alias_list_s handle and releases all its resources from the provided
 *        first handle cascadingly.
 *
 * @since_tizen 2.4
 *
 * @remarks It also destroys the alias in @a ckmc_alias_list_s.
 *
 * @param[in] first The first @a ckmc_alias_list_s handle to destroy
 *
 * @see #ckmc_alias_list_s
 */
void ckmc_alias_list_all_free(ckmc_alias_list_s *first);

/**
 * @brief Creates a new @a ckmc_cert_list_s handle and returns it.
 *        The cert pointer in the returned @a ckmc_cert_list_s handle points to the provided
 *        @a ckmc_cert_s and next is null.
 *
 * @since_tizen 2.4
 *
 * @remarks You must destroy the newly created @a ckmc_cert_list_s by calling ckmc_cert_list_free()
 *          or ckmc_cert_list_all_free() if it is no longer needed.
 *
 * @param[in]  cert          The first item to be set in the newly created @a ckmc_cert_list_s
 * @param[out] ppalias_list  The pointer to a newly created @a ckmc_alias_list_s handle
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_cert_list_s
 */
int ckmc_cert_list_new(ckmc_cert_s *cert, ckmc_cert_list_s **ppalias_list);

/**
 * @brief Creates a new @a ckmc_cert_list_s handle, adds it to a previous @a ckmc_cert_list_s and
 *        returns it. The cert pointer in the returned @a ckmc_alias_list_s handle points to the
 *        provided @a ckmc_cert_s and next is null.
 *
 * @since_tizen 2.4
 *
 * @param[in]  previous  The last @a ckmc_cert_list_s handle to which a newly created
 *                       @a ckmc_cert_list_s is added
 * @param[in]  cert      The item to be set in the newly created @a ckmc_cert_list_s
 * @param[out] pplast    The pointer to a newly created and added @a ckmc_alias_list_s handle
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_cert_list_s
 */
int ckmc_cert_list_add(ckmc_cert_list_s *previous, ckmc_cert_s *cert, ckmc_cert_list_s **pplast);

/**
 * @brief Destroys the @a ckmc_cert_list_s handle and releases resources of @a ckmc_cert_list_s
 *        from the provided first handle cascadingly.
 *
 * @since_tizen 2.4
 *
 * @remarks It does not destroy @a ckmc_cert_s itself in @a ckmc_cert_list_s.
 *
 * @param[in] first The first @a ckmc_cert_list_s handle to destroy
 *
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_cert_list_s
 */
void ckmc_cert_list_free(ckmc_cert_list_s *first);

/**
 * @brief Destroys the @a ckmc_cert_list_s handle and releases all its resources from the provided
 *        first handle cascadingly.
 *
 * @since_tizen 2.3
 *
 * @remarks It also destroys @a ckmc_cert_s in @a ckmc_cert_list_s.
 *
 * @param[in] first The first @a ckmc_cert_list_s handle to destroy
 *
 * @see #ckmc_cert_list_s
 */
void ckmc_cert_list_all_free(ckmc_cert_list_s *first);

/**
 * @brief Creates new parameter list
 *
 * @since_tizen 3.0
 *
 * @remarks Caller is responsible for freeing it with ckmc_param_list_free()
 *
 * @param[in] ppparam_list  Double pointer to the list variable to which the newly created list will
 *                          be assigned
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 *
 * @see ckmc_param_list_add_integer()
 * @see ckmc_param_list_add_buffer()
 * @see ckmc_param_list_free()
 * @see ckmc_generate_params()
 * @see #ckmc_param_list_s
 * @see #ckmc_param_name_e
 */
int ckmc_param_list_new(ckmc_param_list_s **ppparams);

/**
 * @brief Adds integer parameter to the list
 *
 * @since_tizen 3.0
 *
 * @remarks Caller is responsible for @a ckmc_param_list_s creation.
 *
 * @param[in] params    List of params created with ckmc_param_list_new() or
 *                      ckmc_generate_params()
 * @param[in] name      Name of parameter to add \n
 *                      Existing parameter will be overwritten \n
 *                      Passing invalid parameter name will result in an error
 * @param[in] value     Value of the parameter in form of a integer
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 *
 * @see ckmc_param_list_new()
 * @see ckmc_param_list_add_buffer()
 * @see ckmc_param_list_get_integer()
 * @see ckmc_param_list_get_buffer()
 * @see ckmc_param_list_free()
 * @see ckmc_generate_params()
 * @see #ckmc_param_list_s
 * @see #ckmc_param_name_e
 */
int ckmc_param_list_add_integer(ckmc_param_list_s *params,
                                ckmc_param_name_e name,
                                uint64_t value);

/**
 * @brief Adds buffer parameter to the list
 *
 * @since_tizen 3.0
 *
 * @remarks Caller is responsible for @a ckmc_param_list_s creation.
 *
 * @param[in] params    List of params created with ckmc_param_list_new()
 *                      or ckmc_generate_params()
 * @param[in] name      Name of parameter to add \n
 *                      Existing parameter will be overwritten \n
 *                      Passing invalid parameter name will result in an error
 * @param[in] buffer    Value of the parameter in form of a buffer \n
 *                      Caller is responsible for creating and freeing the buffer
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 *
 * @see ckmc_param_list_new()
 * @see ckmc_param_list_add_integer()
 * @see ckmc_param_list_get_integer()
 * @see ckmc_param_list_get_buffer()
 * @see ckmc_param_list_free()
 * @see ckmc_generate_params()
 * @see #ckmc_param_list_s
 * @see #ckmc_param_name_e
 */
int ckmc_param_list_add_buffer(ckmc_param_list_s *params,
                               ckmc_param_name_e name,
                               const ckmc_raw_buffer_s *buffer);

/**
 * @brief Gets integer parameter from the list.
 *
 * @since_tizen 3.0
 *
 * @remarks Caller is responsible for @a ckmc_param_list_s creation.
 *
 * @param[in] params    List of params created with ckmc_param_list_new()
 *                      or ckmc_generate_params()
 * @param[in] name      Name of parameter to get
 * @param[out] value    Value of the parameter in form of a integer
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 *
 * @see ckmc_param_list_new()
 * @see ckmc_param_list_add_integer()
 * @see ckmc_param_list_add_buffer()
 * @see ckmc_param_list_get_buffer()
 * @see ckmc_param_list_free()
 * @see ckmc_generate_params()
 * @see #ckmc_param_list_s
 * @see #ckmc_param_name_e
 */

int ckmc_param_list_get_integer(const ckmc_param_list_s *params,
                                ckmc_param_name_e name,
                                uint64_t* value);

/**
 * @brief Gets buffer parameter from the list.
 *
 * @since_tizen 3.0
 *
 * @remarks Caller is responsible for @a ckmc_param_list_s creation.
 *
 * @param[in] params    List of params created with ckmc_param_list_new()
 *                      or ckmc_generate_params()
 * @param[in] name      Name of parameter to get
 * @param[out] buffer   Value of the parameter in form of a buffer \n
 *                      Caller is responsible for creating and freeing the buffer
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 *
 * @see ckmc_param_list_new()
 * @see ckmc_param_list_add_integer()
 * @see ckmc_param_list_add_buffer()
 * @see ckmc_param_list_get_integer()
 * @see ckmc_param_list_free()
 * @see ckmc_generate_params()
 * @see #ckmc_param_list_s
 * @see #ckmc_param_name_e
 */
int ckmc_param_list_get_buffer(const ckmc_param_list_s *params,
                               ckmc_param_name_e name,
                               ckmc_raw_buffer_s **buffer);

/**
 * @brief Frees previously allocated list of algorithm params
 *
 * @since_tizen 3.0
 *
 * @param[in] first     First element of the list to be freed
 *
 * @see ckmc_param_list_new()
 * @see ckmc_param_list_add_integer()
 * @see ckmc_param_list_add_buffer()
 * @see ckmc_param_list_get_integer()
 * @see ckmc_param_list_get_buffer()
 * @see ckmc_generate_params()
 * @see #ckmc_param_list_s
 * @see #ckmc_param_name_e
 */

void ckmc_param_list_free(ckmc_param_list_s *params);

/**
 * @brief Generates algorithm parameters for a given algorithm type and adds them to the list.
 *
 * @since_tizen 3.0
 *
 * @remarks Caller is responsible for @a ckmc_param_list_s creation and destruction.
 * @remarks Algorithm parameters are set to default values. Optional fields are left empty.
 *          Initialization vectors are left empty (they have to be added manually). Existing params
 *          will be overwritten with default values. Caller is responsible for freeing the list with
 *          ckmc_param_list_free().
 * @remarks If the function returns error, provided param list may contain some of default parameters.
 *
 * @param[in] type      Type of the algorithm
 * @param[out] params   List of params to be filled \n
 *                      List should be empty, otherwise an error will be returned
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                 Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER    Input parameter is invalid
 *
 * @see ckmc_param_list_new()
 * @see ckmc_param_list_add_integer()
 * @see ckmc_param_list_add_buffer()
 * @see ckmc_param_list_get_integer()
 * @see ckmc_param_list_get_buffer()
 * @see ckmc_param_list_free()
 * @see #ckmc_param_list_s
 * @see #ckmc_param_name_e
 */
int ckmc_generate_params(ckmc_algo_type_e type, ckmc_param_list_s *params);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_CORE_CKMC_TYPE_H */
