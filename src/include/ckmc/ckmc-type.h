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
 * @version     1.0
 * @brief       Definitions of struct for the Key Manager's CAPI and their utility functions.
 */

#ifndef __TIZEN_CORE_CKMC_TYPE_H
#define __TIZEN_CORE_CKMC_TYPE_H

#include <stddef.h>
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
 * @brief Enumeration for key types of key manager.
 * @since_tizen 2.3
 */
typedef enum __ckmc_key_type {
    CKMC_KEY_NONE = 0,       /**< key type not specified */
    CKMC_KEY_RSA_PUBLIC,     /**< RSA public key */
    CKMC_KEY_RSA_PRIVATE,    /**< RSA private key */
    CKMC_KEY_ECDSA_PUBLIC,   /**< ECDSA public key */
    CKMC_KEY_ECDSA_PRIVATE,  /**< ECDSA private key */
} ckmc_key_type_e;

/**
 * @brief Enumeration for data format.
 * @since_tizen 2.3
 */
typedef enum __ckmc_data_format {
    CKMC_FORM_DER_BASE64 = 0,  /**< DER format base64 encoded data */
    CKMC_FORM_DER,             /**< DER encoded data */
    CKMC_FORM_PEM              /**< PEM encoded data. It consists of the DER format base64 encoded with additional header and footer lines. */
} ckmc_data_format_e;

/**
 * @brief Enumeration for elliptic curve.
 * @since_tizen 2.3
 */
typedef enum __ckmc_ec_type {
    CKMC_EC_PRIME192V1 = 0, /**< Elliptic curve domain "secp192r1" listed in "SEC 2" recommended elliptic curve domain  */
    CKMC_EC_PRIME256V1,     /**< "SEC 2" recommended elliptic curve domain - secp256r1 */
    CKMC_EC_SECP384R1       /**< NIST curve P-384 (covers "secp384r1", the elliptic curve domain listed in See SEC 2 */
} ckmc_ec_type_e;

/**
 * @brief Enumeration for hash algorithm.
 * @since_tizen 2.3
 */
typedef enum __ckmc_hash_algo {
    CKMC_HASH_SHA1 = 0, /**< Hash Algorithm SHA1  */
    CKMC_HASH_SHA256,   /**< Hash Algorithm SHA256  */
    CKMC_HASH_SHA384,   /**< Hash Algorithm SHA384  */
    CKMC_HASH_SHA512    /**< Hash Algorithm SHA512  */
} ckmc_hash_algo_e;

/**
 * @brief Enumeration for RSA padding algorithm.
 * @since_tizen 2.3
 */
typedef enum __ckmc_rsa_padding_algo {
    CKMC_PKCS1_PADDING = 0, /**< PKCS#1 Padding */
    CKMC_X931_PADDING       /**< X9.31 padding */
} ckmc_rsa_padding_algo_e;

/**
 * @brief the structure for binary buffer used in key manager CAPI.
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
	char* password;   /**< Byte array used to encrypt data inside CKM. If it is not null, the data(or key, or certificate) is stored encrypted with this password inside key manager */
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
	char *alias;  /**< The name of key, certificate or data stored in key manager */
	struct __ckmc_alias_list *next; /**< The pointer pointing to the next ckmc_alias_list_s */
} ckmc_alias_list_s;

/**
 * @brief The structure for linked list of ckmc_cert_s
 * @since_tizen 2.3
 */
typedef struct __ckmc_cert_list {
	ckmc_cert_s *cert; /**< The pointer of ckmc_cert_s */
	struct __ckmc_cert_list *next; /**< The pointer pointing to the next ckmc_cert_list_s */
} ckmc_cert_list_s;

/**
 * @internal
 * @brief Creates a new @a ckmc_key_s handle and returns it.
 *
 * @since_tizen 2.3
 *
 * @remarks You must destroy the newly created @a ckmc_key_s by calling ckmc_key_free() if it is no longer needed.
 *
 * @param[in] raw_key  The byte array of key \n
 *                     @a raw_key may be encrypted with password.
 * @param[in] key_size The byte size of @a raw_key
 * @param[in] key_type The @a raw_key's type
 * @param[in] password The byte array used to decrypt @a raw_key inside key manager \n
 *                     If @a raw_key is not encrypted, @a password can be null.
 * @param[out] ppkey   The pointer to a newly created @a ckmc_key_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_INVALID_PARAMETER Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY     Not enough memory
 *
 * @see ckmc_key_free()
 * @see #ckmc_key_s
 */
int ckmc_key_new(unsigned char *raw_key, size_t key_size,
        ckmc_key_type_e key_type, char *password, ckmc_key_s **ppkey);

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
 * @internal
 * @brief Creates a new @a ckmc_raw_buffer_s handle and returns it.
 *
 * @since_tizen 2.3
 *
 * @remarks You must destroy the newly created @a ckmc_raw_buffer_s by calling ckmc_buffer_free() if it is no longer needed.
 *
 * @param[in]  data      The byte array of buffer
 * @param[in]  size      The byte size of buffer
 * @param[out] ppbuffer  The pointer to a newly created @a ckmc_buffer_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_buffer_free()
 * @see #ckmc_raw_buffer_s
 */
int ckmc_buffer_new(unsigned char *data, size_t size,ckmc_raw_buffer_s **ppbuffer);

/**
 * @brief Destroys the @a ckmc_raw_buffer_s handle and releases all its resources.
 *
 * @since_tizen 2.3
 *
 * @param[in] buffer The @a ckmc_raw_buffer_s handle to destroy
 *
 */
void ckmc_buffer_free(ckmc_raw_buffer_s *buffer);

/**
 * @internal
 * @brief Creates a new @a ckmc_cert_s handle and returns it.
 *
 * @since_tizen 2.3
 *
 * @remarks You must destroy the newly created @a ckmc_cert_s by calling ckmc_cert_free() if it is no longer needed.
 *
 * @param[in]  raw_cert     The byte array of certificate
 * @param[in]  cert_size    The byte size of raw_cert
 * @param[in]  data_format  The encoding format of raw_cert
 * @param[out] ppcert       The pointer to a newly created @a ckmc_cert_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_cert_free()
 * @see ckmc_load_cert_from_file()
 * @see ckmc_load_from_pkcs12_file
 * @see #ckmc_cert_s
 */
int ckmc_cert_new(unsigned char *raw_cert, size_t cert_size,
        ckmc_data_format_e data_format, ckmc_cert_s **ppcert);

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
 * @remarks You must destroy the newly created @a ckmc_cert_s by calling ckmc_cert_free() if it is no longer needed.
 *
 * @param[in]  file_path  The path of certificate file to be loaded \n
 *                        The only DER or PEM encoded certificate file is supported.
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
 * @see ckmc_load_from_pkcs12_file()
 * @see #ckmc_cert_s
 */
int ckmc_load_cert_from_file(const char *file_path, ckmc_cert_s **cert);

/**
 * @brief Creates a new @a ckmc_key_s(private key), @a ckmc_cert_s(certificate), and @a ckmc_cert_list_s(CA certificates) handle from a given PKCS#12 file and returns them.
 *
 * @since_tizen 2.3
 *
 * @remarks You must destroy the newly created @a ckmc_key_s, @a ckmc_cert_s, and @a ckmc_cert_list_s by calling ckmc_key_free(), ckmc_cert_free(), and ckmc_cert_list_all_free() if they are no longer needed.
 *
 * @param[in]  file_path    The path of PKCS12 file to be loaded
 * @param[in]  passphrase   The passphrase used to decrypt the PCKS12 file \n
 *                          If PKCS12 file is not encrypted, passphrase can be null.
 * @param[out] private_key  The pointer of newly created @a ckmc_key_s handle for a private key
 * @param[out] cert         The pointer of newly created @a ckmc_cert_s handle for a certificate \n
 *                          It is null if the PKCS12 file does not contain a certificate.
 * @param[out] ca_cert_list The pointer of newly created @a ckmc_cert_list_s handle for CA certificates \n
 *                          It is null if the PKCS12 file does not contain CA certificates.
 *
 * @return #CKMC_ERROR_NONE on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                Successful
 * @retval #CKMC_ERROR_OUT_OF_MEMORY       Not enough memory space
 * @retval #CKMC_ERROR_INVALID_FORMAT      Invalid PKCS12 file format
 * @retval #CKMC_ERROR_FILE_ACCESS_DENIED  Provided file does not exist or cannot be accessed
 *
 * @see ckmc_key_free()
 * @see ckmc_cert_free()
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_key_s
 * @see #ckmc_cert_s
 * @see #ckmc_cert_list_s
 */
int ckmc_load_from_pkcs12_file(const char *file_path, const char *passphrase,
        ckmc_key_s **private_key, ckmc_cert_s **cert,
        ckmc_cert_list_s **ca_cert_list);

/**
 * @internal
 * @brief Creates a new @a ckmc_alias_list_s handle and returns it.
 *        The alias pointer in the returned @a ckmc_alias_list_s handle points to the provided characters and next is null.
 *
 * @since_tizen 2.3
 *
 * @remarks You must destroy the newly created @a ckmc_alias_list_s by calling ckmc_alias_list_free() or ckmc_alias_list_all_free() if it is no longer needed.
 *
 * @param[in]  alias        The first item to be set in the newly created @a ckmc_alias_list_s
 * @param[out] ppalias_list The pointer to a newly created @a ckmc_alias_list_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_INVALID_PARAMETER Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY     Not enough memory
 *
 * @see ckmc_alias_list_all_free()
 * @see #ckmc_alias_list_s
 */
int ckmc_alias_list_new(char *alias, ckmc_alias_list_s **ppalias_list);

/**
 * @internal
 * @brief Creates a new @a ckmc_alias_list_s handle, adds it to a previous @a ckmc_alias_list_s and returns it.
 *        The alias pointer in the returned @a ckmc_alias_list_s handle points to the provided characters and next is null.
 *
 * @since_tizen 2.3
 *
 * @param[in]  previous  The last @a ckmc_alias_list_s handle to which a newly created @a ckmc_alias_list_s is added
 * @param[in]  alias     The item to be set in the newly created @a ckmc_alias_list_s
 * @param[out] pplast    The pointer to a newly created and added @a ckmc_alias_list_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_alias_list_all_free()
 * @see #ckmc_alias_list_s
 */
int ckmc_alias_list_add(ckmc_alias_list_s *previous,
        char *alias, ckmc_alias_list_s **pplast);

/**
 * @internal
 * @brief Destroys the @a ckmc_alias_list_s handle and releases resources of @a ckmc_alias_list_s from the provided first handle cascadingly.
 *
 * @since_tizen 2.3
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
 * @brief Destroys the @a ckmc_alias_list_s handle and releases all its resources from the provided first handle cascadingly.
 *
 * @since_tizen 2.3
 *
 * @remarks It also destroys the alias in @a ckmc_alias_list_s.
 *
 * @param[in] first The first @a ckmc_alias_list_s handle to destroy
 *
 * @see #ckmc_alias_list_s
 */
void ckmc_alias_list_all_free(ckmc_alias_list_s *first);

/**
 * @internal
 * @brief Creates a new @a ckmc_cert_list_s handle and returns it.
 *        The cert pointer in the returned @a ckmc_cert_list_s handle points to the provided @a ckmc_cert_s and next is null.
 *
 * @since_tizen 2.3
 *
 * @remarks You must destroy the newly created @a ckmc_cert_list_s by calling ckmc_cert_list_free() or ckmc_cert_list_all_free() if it is no longer needed.
 *
 * @param[in]  cert          The first item to be set in the newly created @a ckmc_cert_list_s
 * @param[out] ppalias_list  The pointer to a newly created @a ckmc_alias_list_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_cert_list_s
 */
int ckmc_cert_list_new(ckmc_cert_s *cert, ckmc_cert_list_s **ppalias_list);

/**
 * @internal
 * @brief Creates a new @a ckmc_cert_list_s handle, adds it to a previous @a ckmc_cert_list_s and returns it.
 *        The cert pointer in the returned @a ckmc_alias_list_s handle points to the provided @a ckmc_cert_s and next is null.
 *
 * @since_tizen 2.3
 *
 * @param[in]  previous  The last @a ckmc_cert_list_s handle to which a newly created @a ckmc_cert_list_s is added
 * @param[in]  cert      The item to be set in the newly created @a ckmc_cert_list_s
 * @param[out] pplast    The pointer to a newly created and added @a ckmc_alias_list_s handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Input parameter is invalid
 * @retval #CKMC_ERROR_OUT_OF_MEMORY      Not enough memory
 *
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_cert_list_s
 */
int ckmc_cert_list_add(ckmc_cert_list_s *previous,
        ckmc_cert_s *cert, ckmc_cert_list_s **pplast);

/**
 * @internal
 * @brief Destroys the @a ckmc_cert_list_s handle and releases resources of @a ckmc_cert_list_s from the provided first handle cascadingly.
 *
 * @since_tizen 2.3
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
 * @brief Destroys the @a ckmc_cert_list_s handle and releases all its resources from the provided first handle cascadingly.
 *
 * @since_tizen 2.3
 *
 * @remarks It also destroys @a ckmc_cert_s in ckmc_cert_list_s.
 *
 * @param[in] first The first @a ckmc_cert_list_s handle to destroy
 *
 * @see #ckmc_cert_list_s
 */
void ckmc_cert_list_all_free(ckmc_cert_list_s *first);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_CORE_CKMC_TYPE_H */
