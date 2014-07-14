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
 * @brief       Definitions of struct for the Key Manager's CAPI and their utility functions
 */

#ifndef __TIZEN_CORE_CKMC_TYPE_H
#define __TIZEN_CORE_CKMC_TYPE_H

#include <stddef.h>

#define KEY_MANAGER_CAPI __attribute__((visibility("default")))


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_KEY_MANAGER_MODULE
 * @{
 */

/**
 * @brief Enumeration for key types of key manager.
 */
typedef enum ckm_key_type_t {
    CKM_KEY_NONE =0,         /**< key type not specified */
    CKM_KEY_RSA_PUBLIC,      /**< RSA public key */
    CKM_KEY_RSA_PRIVATE,     /**< RSA private key */
    CKM_KEY_ECDSA_PUBLIC,    /**< ECDSA public key */
    CKM_KEY_ECDSA_PRIVATE,   /**< ECDSA private key */
} ckm_key_type;

/**
 * @brief Enumeration for data format.
 */
typedef enum ckm_data_format_t {
	CKM_FORM_DER_BASE64 =0, /**< DER format base64 encoded data */
	CKM_FORM_DER,           /**< DER encoded data */
	CKM_FORM_PEM            /**< PEM encoded data. It consists of the DER format base64 encoded with additional header and footer lines */
} ckm_data_format;

/**
 * @brief Enumeration for eliptic curve.
 */
typedef enum ckm_ec_type_t {
	CKM_EC_PRIME192V1 =0,  /**< Elliptic curve domain "secp192r1" listed in "SEC 2" recommended elliptic curve domain  */
	CKM_EC_PRIME256V1,     /**< "SEC 2" recommended elliptic curve domain - secp256r1 */
	CKM_EC_SECP384R1       /**< NIST curve P-384 (covers "secp384r1", the elliptic curve domain listed in See SEC 2 */
} ckm_ec_type;

/**
 * @brief Enumeration for bool type used within key manager CAPI.
 */
typedef enum ckm_bool_t {
	CKM_FALSE =0,        /**< false  */
	CKM_TRUE             /**< true  */
} ckm_bool;

/**
 * @brief Enumeration for hash algorithm.
 */
typedef enum ckm_hash_algo_t {
	CKM_HASH_SHA1 =0,   /**< Hash Algorithm SHA1  */
	CKM_HASH_SHA256,    /**< Hash Algorithm SHA256  */
	CKM_HASH_SHA384,    /**< Hash Algorithm SHA384  */
	CKM_HASH_SHA512     /**< Hash Algorithm SHA512  */
} ckm_hash_algo;

/**
 * @brief Enumeration for RSA padding algorithm.
 */
typedef enum ckm_rsa_padding_algo_t {
    CKM_PKCS1_PADDING =0, /**< PKCS#1 Padding */
    CKM_X931_PADDING      /**< X9.31 padding */
} ckm_rsa_padding_algo;




/**
 * @brief binary buffer used in key manager CAPI
 * @details @a data is byte array containing some binary data
 *          @a size is the size of the binary data
 */
typedef struct ckm_raw_buff_t{
	unsigned char* data;
	size_t         size;
} ckm_raw_buffer;

/**
 * @brief a policy for storing key/certificate/binary data
 * @details if @a password is not null, the data(or key, or certificate) is stored encrypted with this password inside key manager
 *          if @a extractable true, key may be extracted from storage
 *          if @a restricted true, only key owner can see data
 */
typedef struct ckm_policy_t {
	char*          password;  // byte array used to encrypt data inside CKM
	ckm_bool       extractable;  // if true key may be extracted from storage
	ckm_bool       restricted;   // if true only key owner may see data
} ckm_policy;

/**
 * @brief key structure used in key manager CAPI
 * @details @a raw_key is byte array of key. raw_key may be encrypted with password.
 *          @a key_size is the byte size of raw_key
 *          @a key_type is the raw_key's type
 *          if @a password is byte array used to decrypt raw_key inside key manager.
 */
typedef struct ckm_key_t {
	unsigned char* raw_key;
	size_t         key_size;
	ckm_key_type   key_type;
	char*          password;  // byte array used to decrypt data raw_key inside key manager
} ckm_key;

/**
 * @brief certificate structure used in key manager CAPI
 * @details @a raw_cert is byte array of certificate.
 *          @a cert_size is the byte size of raw_cert
 *          @a data_format is the raw_cert's encoding format
 */
typedef struct ckm_cert_t {
	unsigned char*  raw_cert;
	size_t          cert_size;
	ckm_data_format data_format;
} ckm_cert;

/**
 * @brief linked list structure of alias
 * @details @a alias is a name of key, certificate or data stored in key manager.
 *          @a next is a pointer pointing to the next ckm_alias_list
 */
typedef struct ckm_alias_list_t {
	char *alias;
	struct ckm_alias_list_t *next;
} ckm_alias_list;

/**
 * @brief linked list structure of ckm_cert
 * @details @a cert is a pointer of ckm_cert.
 *          @a next is a pointer pointing to the next ckm_cert_list
 */
typedef struct ckm_cert_list_t {
	ckm_cert *cert;
	struct ckm_cert_list_t *next;
} ckm_cert_list;




/**
 * @brief Creates a new ckm_key handle and returns it.
 *
 * @remarks A newly created ckm_key should be destroyed by calling ckm_key_free() if it is no longer needed.
 *
 * @param[in] raw_key is byte array of key. raw_key may be encrypted with password
 * @param[in] key_size is the byte size of raw_key
 * @param[in] key_type is the raw_key's type
 * @param[in] password is byte array used to decrypt raw_key inside key manager. If raw_key is not encrypted, password can be null.
 * @return a newly created ckm_key handle
 * @retval If successful, a newly created ckm_key handle will be returned
 * @retval If out of memory, returns a null value.
 * @see ckm_key_free()
 * @see #ckm_key
 */
ckm_key *ckm_key_new(unsigned char *raw_key, size_t key_size, ckm_key_type key_type, char *password);

/**
 * @brief Destroys the ckm_key handle and releases all its resources.
 * @param[in] key a ckm_key handle to destroy
 * @see ckm_key_new()
 */
void ckm_key_free(ckm_key *key);




/**
 * @brief Creates a new ckm_raw_buffer handle and returns it.
 *
 * @remarks A newly created ckm_raw_buffer should be destroyed by calling ckm_buffer_free() if it is no longer needed.
 *
 * @param[in] data is byte array of buffer.
 * @param[in] size is the byte size of buffer
 * @return a newly created ckm_raw_buffer handle
 * @retval If successful, a newly created ckm_raw_buffer handle will be returned
 * @retval If out of memory, returns a null value.
 * @see ckm_buffer_free()
 * @see #ckm_raw_buffer
 */
ckm_raw_buffer * ckm_buffer_new(unsigned char *data, size_t size);

/**
 * @brief Destroys the ckm_raw_buffer handle and releases all its resources.
 * @param[in] buffer a ckm_raw_buffer handle to destroy
 * @see ckm_buffer_new()
 */
void ckm_buffer_free(ckm_raw_buffer *buffer);




/**
 * @brief Creates a new ckm_cert handle and returns it.
 *
 * @remarks A newly created ckm_cert should be destroyed by calling ckm_cert_free() if it is no longer needed.
 *
 * @param[in] raw_cert is byte array of certificate.
 * @param[in] cert_size is the byte size of raw_cert.
 * @param[in] data_format is the encoding format of raw_cert
 * @return a newly created ckm_cert handle
 * @retval If successful, a newly created ckm_cert handle will be returned
 * @retval If out of memory, returns a null value.
 * @see ckm_cert_free()
 * @see ckm_load_cert_from_file()
 * @see ckm_load_from_pkcs12_file
 * @see #ckm_cert
 */
ckm_cert *ckm_cert_new(unsigned char *raw_cert, size_t cert_size, ckm_data_format data_format);

/**
 * @brief Destroys the ckm_cert handle and releases all its resources.
 * @param[in] buffer a ckm_cert handle to destroy
 * @see ckm_cert_new()
 * @see ckm_load_cert_from_file()
 * @see ckm_load_from_pkcs12_file
 */
void ckm_cert_free(ckm_cert *cert);

/**
 * @brief Create a new ckm_cert handle from a given file and returns it.
 *
 * @remarks A newly created ckm_cert should be destroyed by calling ckm_cert_free() if it is no longer needed.
 *
 * @param[in] file_path is a path of certificate file to be loaded. The  only DER or PEM encoded certificate file is supported.
 * @param[out] cert is the pointer of newly created ckm_cert handle
 * @return #CKM_API_SUCCESS on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_OUT_OF_MEMORY not enough memory space
 * @retval #CKM_API_ERROR_INVALID_FORMAT invalid certificate file format
 * @retval #CKM_API_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 * @see ckm_cert_free()
 * @see ckm_cert_new()
 * @see ckm_load_from_pkcs12_file()
 * @see #ckm_cert
 */
int ckm_load_cert_from_file(const char *file_path, ckm_cert **cert);

/**
 * @brief Create a new ckm_key(private key), ckm_cert(certificate), and ckm_cert_list(CA certificates) handle from a given PKCS#12 file and returns them.
 *
 * @remarks A newly created ckm_key, ckm_cert, and ckm_cert_list should be destroyed by calling ckm_key_free(), ckm_cert_free(), and ckm_cert_list_all_free() if they are no longer needed.
 *
 * @param[in] file_path is a path of PKCS12 file to be loaded.
 * @param[in] passphrase is used to decrypt the PCKS12 file. If PKCS12 file is not encrypted, passphrase can be null.
 * @param[out] private_key is the pointer of newly created ckm_key handle for a private key
 * @param[out] cert is the pointer of newly created ckm_cert handle for a certificate. It is null if the PKCS12 file doesn't contain a certificate.
 * @param[out] ca_cert_list is the pointer of newly created ckm_cert_list handle for CA certificates. It is null if the PKCS12 file doesn't contain CA certificates.
 * @return #CKM_API_SUCCESS on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_OUT_OF_MEMORY not enough memory space
 * @retval #CKM_API_ERROR_INVALID_FORMAT invalid PKCS12 file format
 * @retval #CKM_API_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 * @see ckm_key_free()
 * @see ckm_cert_free()
 * @see ckm_cert_list_all_free()
 * @see #ckm_key
 * @see #ckm_cert
 * @see #ckm_cert_list
 */
int ckm_load_from_pkcs12_file(const char *file_path, const char *passphrase, ckm_key **private_key, ckm_cert **cert, ckm_cert_list **ca_cert_list);



/**
 * @brief Creates a new ckm_alias_list handle and returns it. The alias pointer in the returned ckm_alias_list handle points to the provided characters and the next is null.
 *
 * @remarks A newly created ckm_alias_list should be destroyed by calling ckm_alias_list_free() or ckm_alias_list_all_free() if it is no longer needed.
 *
 * @param[in] alias is the first item to be set in the newly created ckm_alias_list.
 * @return a newly created ckm_alias_list handle
 * @retval If successful, a newly created ckm_alias_list handle will be returned
 * @retval If out of memory, returns a null value.
 * @see ckm_alias_list_add()
 * @see ckm_alias_list_free()
 * @see ckm_alias_list_all_free()
 * @see #ckm_alias_list
 */
ckm_alias_list *ckm_alias_list_new(char *alias);

/**
 * @brief Creates a new ckm_alias_list handle, add it to a previous ckm_alias_list and returns it. The alias pointer in the returned ckm_alias_list handle points to the provided characters and the next is null.
 *
 * @param[in] previous the last ckm_alias_list handle to which a newly created ckm_alias_list is added
 * @param[in] alias is an item to be set in the newly created ckm_alias_list.
 * @return a newly added ckm_alias_list handle. It should be given as previous when ckm_cert_list_add() is called again.
 * @retval If successful, a newly created ckm_alias_list handle will be returned
 * @retval If out of memory, returns a null value.
 * @see ckm_alias_list_add()
 * @see ckm_alias_list_free()
 * @see ckm_alias_list_all_free()
 * @see #ckm_alias_list
 */
ckm_alias_list *ckm_alias_list_add(ckm_alias_list *previous, char *alias);

/**
 * @brief Destroys the ckm_alias_list handle and releases resources of ckm_alias_list from the provided first handle cascadingly.
 *
 * @remarks It does not destroy an alias itself in ckm_alias_list.
 *
 * @param[in] buffer the first ckm_alias_list handle to destroy
 * @see ckm_alias_list_new()
 * @see ckm_alias_list_add()
 * @see ckm_alias_list_all_free()
 * @see #ckm_alias_list
 */
void ckm_alias_list_free(ckm_alias_list *first);

/**
 * @brief Destroys the ckm_alias_list handle and releases all its resources from the provided first handle cascadingly.
 *
 * @remarks It also destroy an alias in ckm_alias_list.
 *
 * @param[in] buffer the first ckm_alias_list handle to destroy
 * @see ckm_alias_list_new()
 * @see ckm_alias_list_add()
 * @see ckm_alias_list_free()
 * @see #ckm_alias_list
 */
void ckm_alias_list_all_free(ckm_alias_list *cert_list);




/**
 * @brief Creates a new ckm_cert_list handle and returns it. The cert pointer in the returned ckm_cert_list handle points to the provided ckm_cert and the next is null.
 *
 * @remarks A newly created ckm_cert_list should be destroyed by calling ckm_cert_list_free() or ckm_cert_list_all_free() if it is no longer needed.
 *
 * @param[in] cert is the first item to be set in the newly created ckm_cert_list.
 * @return a newly created ckm_cert_list handle
 * @retval If successful, a newly created ckm_cert_list handle will be returned
 * @retval If out of memory, returns a null value.
 * @see ckm_cert_list_add()
 * @see ckm_cert_list_free()
 * @see ckm_cert_list_all_free()
 * @see #ckm_cert_list
 */
ckm_cert_list *ckm_cert_list_new(ckm_cert *cert);

/**
 * @brief Creates a new ckm_cert_list handle, add it to a previous ckm_cert_list and returns it. The cert pointer in the returned ckm_alias_list handle points to the provided ckm_cert and the next is null.
 *
 * @param[in] previous the last ckm_cert_list handle to which a newly created ckm_cert_list is added
 * @param[in] cert is an item to be set in the newly created ckm_cert_list.
 * @return a newly added ckm_cert_list handle. It should be given as previous when ckm_cert_list_add() is called again.
 * @retval If successful, a newly created ckm_cert_list handle will be returned
 * @retval If out of memory, returns a null value.
 * @see ckm_cert_list_add()
 * @see ckm_cert_list_free()
 * @see ckm_cert_list_all_free()
 * @see #ckm_cert_list
 */
ckm_cert_list *ckm_cert_list_add(ckm_cert_list *previous, ckm_cert *cert);

/**
 * @brief Destroys the ckm_cert_list handle and releases resources of ckm_cert_list from the provided first handle cascadingly.
 *
 * @remarks It does not destroy an ckm_cert itself in ckm_cert_list.
 *
 * @param[in] buffer the first ckm_cert_list handle to destroy
 * @see ckm_cert_list_new()
 * @see ckm_cert_list_add()
 * @see ckm_cert_list_all_free()
 * @see #ckm_cert_list
 */
void ckm_cert_list_free(ckm_cert_list *first);

/**
 * @brief Destroys the ckm_cert_list handle and releases all its resources from the provided first handle cascadingly.
 *
 * @remarks It also destroy an ckm_cert in ckm_cert_list.
 *
 * @param[in] buffer the first ckm_cert_list handle to destroy
 * @see ckm_cert_list_new()
 * @see ckm_cert_list_add()
 * @see ckm_cert_list_free()
 * @see #ckm_cert_list
 */
void ckm_cert_list_all_free(ckm_cert_list *cert_list);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_CORE_CKMC_TYPE_H */
