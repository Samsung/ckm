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
typedef enum ckmc_key_type_t {
    CKMC_KEY_NONE =0,         /**< key type not specified */
    CKMC_KEY_RSA_PUBLIC,      /**< RSA public key */
    CKMC_KEY_RSA_PRIVATE,     /**< RSA private key */
    CKMC_KEY_ECDSA_PUBLIC,    /**< ECDSA public key */
    CKMC_KEY_ECDSA_PRIVATE,   /**< ECDSA private key */
} ckmc_key_type;

/**
 * @brief Enumeration for data format.
 */
typedef enum ckmc_data_format_t {
	CKMC_FORM_DER_BASE64 =0, /**< DER format base64 encoded data */
	CKMC_FORM_DER,           /**< DER encoded data */
	CKMC_FORM_PEM            /**< PEM encoded data. It consists of the DER format base64 encoded with additional header and footer lines */
} ckmc_data_format;

/**
 * @brief Enumeration for eliptic curve.
 */
typedef enum ckmc_ec_type_t {
	CKMC_EC_PRIME192V1 =0,  /**< Elliptic curve domain "secp192r1" listed in "SEC 2" recommended elliptic curve domain  */
	CKMC_EC_PRIME256V1,     /**< "SEC 2" recommended elliptic curve domain - secp256r1 */
	CKMC_EC_SECP384R1       /**< NIST curve P-384 (covers "secp384r1", the elliptic curve domain listed in See SEC 2 */
} ckmc_ec_type;

/**
 * @brief Enumeration for bool type used within key manager CAPI.
 */
typedef enum ckmc_bool_t {
	CKMC_FALSE =0,        /**< false  */
	CKMC_TRUE             /**< true  */
} ckmc_bool;

/**
 * @brief Enumeration for hash algorithm.
 */
typedef enum ckmc_hash_algo_t {
	CKMC_HASH_SHA1 =0,   /**< Hash Algorithm SHA1  */
	CKMC_HASH_SHA256,    /**< Hash Algorithm SHA256  */
	CKMC_HASH_SHA384,    /**< Hash Algorithm SHA384  */
	CKMC_HASH_SHA512     /**< Hash Algorithm SHA512  */
} ckmc_hash_algo;

/**
 * @brief Enumeration for RSA padding algorithm.
 */
typedef enum ckmc_rsa_padding_algo_t {
    CKMC_PKCS1_PADDING =0, /**< PKCS#1 Padding */
    CKMC_X931_PADDING      /**< X9.31 padding */
} ckmc_rsa_padding_algo;




/**
 * @brief binary buffer used in key manager CAPI
 * @details @a data is byte array containing some binary data
 *          @a size is the size of the binary data
 */
typedef struct ckmc_raw_buff_t{
	unsigned char* data;
	size_t         size;
} ckmc_raw_buffer;

/**
 * @brief a policy for storing key/certificate/binary data
 * @details if @a password is not null, the data(or key, or certificate) is stored encrypted with this password inside key manager
 *          if @a extractable true, key may be extracted from storage
 *          if @a restricted true, only key owner can see data
 */
typedef struct ckmc_policy_t {
	char*          password;  // byte array used to encrypt data inside CKM
	ckmc_bool       extractable;  // if true key may be extracted from storage
	ckmc_bool       restricted;   // if true only key owner may see data
} ckmc_policy;

/**
 * @brief key structure used in key manager CAPI
 * @details @a raw_key is byte array of key. raw_key may be encrypted with password.
 *          @a key_size is the byte size of raw_key
 *          @a key_type is the raw_key's type
 *          if @a password is byte array used to decrypt raw_key inside key manager.
 */
typedef struct ckmc_key_t {
	unsigned char* raw_key;
	size_t         key_size;
	ckmc_key_type   key_type;
	char*          password;  // byte array used to decrypt data raw_key inside key manager
} ckmc_key;

/**
 * @brief certificate structure used in key manager CAPI
 * @details @a raw_cert is byte array of certificate.
 *          @a cert_size is the byte size of raw_cert
 *          @a data_format is the raw_cert's encoding format
 */
typedef struct ckmc_cert_t {
	unsigned char*  raw_cert;
	size_t          cert_size;
	ckmc_data_format data_format;
} ckmc_cert;

/**
 * @brief linked list structure of alias
 * @details @a alias is a name of key, certificate or data stored in key manager.
 *          @a next is a pointer pointing to the next ckmc_alias_list
 */
typedef struct ckmc_alias_list_t {
	char *alias;
	struct ckmc_alias_list_t *next;
} ckmc_alias_list;

/**
 * @brief linked list structure of ckmc_cert
 * @details @a cert is a pointer of ckmc_cert.
 *          @a next is a pointer pointing to the next ckmc_cert_list
 */
typedef struct ckmc_cert_list_t {
	ckmc_cert *cert;
	struct ckmc_cert_list_t *next;
} ckmc_cert_list;




/**
 * @brief Creates a new ckmc_key handle and returns it.
 *
 * @remarks A newly created ckmc_key should be destroyed by calling ckmc_key_free() if it is no longer needed.
 *
 * @param[in] raw_key is byte array of key. raw_key may be encrypted with password
 * @param[in] key_size is the byte size of raw_key
 * @param[in] key_type is the raw_key's type
 * @param[in] password is byte array used to decrypt raw_key inside key manager. If raw_key is not encrypted, password can be null.
 * @return a newly created ckmc_key handle
 * @exception If successful, a newly created ckmc_key handle will be returned
 * @exception If out of memory, returns a null value.
 * @see ckmc_key_free()
 * @see #ckmc_key
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
ckmc_key *ckmc_key_new(unsigned char *raw_key, size_t key_size, ckmc_key_type key_type, char *password);

/**
 * @brief Destroys the ckmc_key handle and releases all its resources.
 * @param[in] key a ckmc_key handle to destroy
 * @see ckmc_key_new()
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
void ckmc_key_free(ckmc_key *key);




/**
 * @brief Creates a new ckmc_raw_buffer handle and returns it.
 *
 * @remarks A newly created ckmc_raw_buffer should be destroyed by calling ckmc_buffer_free() if it is no longer needed.
 *
 * @param[in] data is byte array of buffer.
 * @param[in] size is the byte size of buffer
 * @return a newly created ckmc_raw_buffer handle
 * @exception If successful, a newly created ckmc_raw_buffer handle will be returned
 * @exception If out of memory, returns a null value.
 * @see ckmc_buffer_free()
 * @see #ckmc_raw_buffer
 */
ckmc_raw_buffer * ckmc_buffer_new(unsigned char *data, size_t size);

/**
 * @brief Destroys the ckmc_raw_buffer handle and releases all its resources.
 * @param[in] buffer a ckmc_raw_buffer handle to destroy
 * @see ckmc_buffer_new()
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
void ckmc_buffer_free(ckmc_raw_buffer *buffer);




/**
 * @brief Creates a new ckmc_cert handle and returns it.
 *
 * @remarks A newly created ckmc_cert should be destroyed by calling ckmc_cert_free() if it is no longer needed.
 *
 * @param[in] raw_cert is byte array of certificate.
 * @param[in] cert_size is the byte size of raw_cert.
 * @param[in] data_format is the encoding format of raw_cert
 * @return a newly created ckmc_cert handle
 * @exception If successful, a newly created ckmc_cert handle will be returned
 * @exception If out of memory, returns a null value.
 * @see ckmc_cert_free()
 * @see ckmc_load_cert_from_file()
 * @see ckmc_load_from_pkcs12_file
 * @see #ckmc_cert
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
ckmc_cert *ckmc_cert_new(unsigned char *raw_cert, size_t cert_size, ckmc_data_format data_format);

/**
 * @brief Destroys the ckmc_cert handle and releases all its resources.
 * @param[in] cert a ckmc_cert handle to destroy
 * @see ckmc_cert_new()
 * @see ckmc_load_cert_from_file()
 * @see ckmc_load_from_pkcs12_file
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
void ckmc_cert_free(ckmc_cert *cert);

/**
 * @brief Create a new ckmc_cert handle from a given file and returns it.
 *
 * @remarks A newly created ckmc_cert should be destroyed by calling ckmc_cert_free() if it is no longer needed.
 *
 * @param[in] file_path is a path of certificate file to be loaded. The  only DER or PEM encoded certificate file is supported.
 * @param[out] cert is the pointer of newly created ckmc_cert handle
 * @return #CKMC_API_SUCCESS on success, otherwise a negative error value
 * @exception #CKMC_API_SUCCESS Successful
 * @exception #CKMC_API_ERROR_OUT_OF_MEMORY not enough memory space
 * @exception #CKMC_API_ERROR_INVALID_FORMAT invalid certificate file format
 * @exception #CKMC_API_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 * @see ckmc_cert_free()
 * @see ckmc_cert_new()
 * @see ckmc_load_from_pkcs12_file()
 * @see #ckmc_cert
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
int ckmc_load_cert_from_file(const char *file_path, ckmc_cert **cert);

/**
 * @brief Create a new ckmc_key(private key), ckmc_cert(certificate), and ckmc_cert_list(CA certificates) handle from a given PKCS#12 file and returns them.
 *
 * @remarks A newly created ckmc_key, ckmc_cert, and ckmc_cert_list should be destroyed by calling ckmc_key_free(), ckmc_cert_free(), and ckmc_cert_list_all_free() if they are no longer needed.
 *
 * @param[in] file_path is a path of PKCS12 file to be loaded.
 * @param[in] passphrase is used to decrypt the PCKS12 file. If PKCS12 file is not encrypted, passphrase can be null.
 * @param[out] private_key is the pointer of newly created ckmc_key handle for a private key
 * @param[out] cert is the pointer of newly created ckmc_cert handle for a certificate. It is null if the PKCS12 file doesn't contain a certificate.
 * @param[out] ca_cert_list is the pointer of newly created ckmc_cert_list handle for CA certificates. It is null if the PKCS12 file doesn't contain CA certificates.
 * @return #CKMC_API_SUCCESS on success, otherwise a negative error value
 * @exception #CKMC_API_SUCCESS Successful
 * @exception #CKMC_API_ERROR_OUT_OF_MEMORY not enough memory space
 * @exception #CKMC_API_ERROR_INVALID_FORMAT invalid PKCS12 file format
 * @exception #CKMC_API_ERROR_FILE_ACCESS_DENIED provided file doesn't exists or cannot be accessed
 * @see ckmc_key_free()
 * @see ckmc_cert_free()
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_key
 * @see #ckmc_cert
 * @see #ckmc_cert_list
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
int ckmc_load_from_pkcs12_file(const char *file_path, const char *passphrase, ckmc_key **private_key, ckmc_cert **cert, ckmc_cert_list **ca_cert_list);



/**
 * @brief Creates a new ckmc_alias_list handle and returns it. The alias pointer in the returned ckmc_alias_list handle points to the provided characters and the next is null.
 *
 * @remarks A newly created ckmc_alias_list should be destroyed by calling ckmc_alias_list_free() or ckmc_alias_list_all_free() if it is no longer needed.
 *
 * @param[in] alias is the first item to be set in the newly created ckmc_alias_list.
 * @return a newly created ckmc_alias_list handle
 * @exception If successful, a newly created ckmc_alias_list handle will be returned
 * @exception If out of memory, returns a null value.
 * @see ckmc_alias_list_add()
 * @see ckmc_alias_list_free()
 * @see ckmc_alias_list_all_free()
 * @see #ckmc_alias_list
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
ckmc_alias_list *ckmc_alias_list_new(char *alias);

/**
 * @brief Creates a new ckmc_alias_list handle, add it to a previous ckmc_alias_list and returns it. The alias pointer in the returned ckmc_alias_list handle points to the provided characters and the next is null.
 *
 * @param[in] previous the last ckmc_alias_list handle to which a newly created ckmc_alias_list is added
 * @param[in] alias is an item to be set in the newly created ckmc_alias_list.
 * @return a newly added ckmc_alias_list handle. It should be given as previous when ckmc_cert_list_add() is called again.
 * @exception If successful, a newly created ckmc_alias_list handle will be returned
 * @exception If out of memory, returns a null value.
 * @see ckmc_alias_list_add()
 * @see ckmc_alias_list_free()
 * @see ckmc_alias_list_all_free()
 * @see #ckmc_alias_list
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
ckmc_alias_list *ckmc_alias_list_add(ckmc_alias_list *previous, char *alias);

/**
 * @brief Destroys the ckmc_alias_list handle and releases resources of ckmc_alias_list from the provided first handle cascadingly.
 *
 * @remarks It does not destroy an alias itself in ckmc_alias_list.
 *
 * @param[in] first the first ckmc_alias_list handle to destroy
 * @see ckmc_alias_list_new()
 * @see ckmc_alias_list_add()
 * @see ckmc_alias_list_all_free()
 * @see #ckmc_alias_list
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
void ckmc_alias_list_free(ckmc_alias_list *first);

/**
 * @brief Destroys the ckmc_alias_list handle and releases all its resources from the provided first handle cascadingly.
 *
 * @remarks It also destroy an alias in ckmc_alias_list.
 *
 * @param[in] first the first ckmc_alias_list handle to destroy
 * @see ckmc_alias_list_new()
 * @see ckmc_alias_list_add()
 * @see ckmc_alias_list_free()
 * @see #ckmc_alias_list
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
void ckmc_alias_list_all_free(ckmc_alias_list *first);




/**
 * @brief Creates a new ckmc_cert_list handle and returns it. The cert pointer in the returned ckmc_cert_list handle points to the provided ckmc_cert and the next is null.
 *
 * @remarks A newly created ckmc_cert_list should be destroyed by calling ckmc_cert_list_free() or ckmc_cert_list_all_free() if it is no longer needed.
 *
 * @param[in] cert is the first item to be set in the newly created ckmc_cert_list.
 * @return a newly created ckmc_cert_list handle
 * @exception If successful, a newly created ckmc_cert_list handle will be returned
 * @exception If out of memory, returns a null value.
 * @see ckmc_cert_list_add()
 * @see ckmc_cert_list_free()
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_cert_list
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
ckmc_cert_list *ckmc_cert_list_new(ckmc_cert *cert);

/**
 * @brief Creates a new ckmc_cert_list handle, add it to a previous ckmc_cert_list and returns it. The cert pointer in the returned ckmc_alias_list handle points to the provided ckmc_cert and the next is null.
 *
 * @param[in] previous the last ckmc_cert_list handle to which a newly created ckmc_cert_list is added
 * @param[in] cert is an item to be set in the newly created ckmc_cert_list.
 * @return a newly added ckmc_cert_list handle. It should be given as previous when ckmc_cert_list_add() is called again.
 * @exception If successful, a newly created ckmc_cert_list handle will be returned
 * @exception If out of memory, returns a null value.
 * @see ckmc_cert_list_add()
 * @see ckmc_cert_list_free()
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_cert_list
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
ckmc_cert_list *ckmc_cert_list_add(ckmc_cert_list *previous, ckmc_cert *cert);

/**
 * @brief Destroys the ckmc_cert_list handle and releases resources of ckmc_cert_list from the provided first handle cascadingly.
 *
 * @remarks It does not destroy an ckmc_cert itself in ckmc_cert_list.
 *
 * @param[in] first the first ckmc_cert_list handle to destroy
 * @see ckmc_cert_list_new()
 * @see ckmc_cert_list_add()
 * @see ckmc_cert_list_all_free()
 * @see #ckmc_cert_list
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
void ckmc_cert_list_free(ckmc_cert_list *first);

/**
 * @brief Destroys the ckmc_cert_list handle and releases all its resources from the provided first handle cascadingly.
 *
 * @remarks It also destroy an ckmc_cert in ckmc_cert_list.
 *
 * @param[in] first the first ckmc_cert_list handle to destroy
 * @see ckmc_cert_list_new()
 * @see ckmc_cert_list_add()
 * @see ckmc_cert_list_free()
 * @see #ckmc_cert_list
 *
 * @since 2.3
 * @privlevel public
 * @privilege %http://tizen.org/privilege/keymanager *
 */
void ckmc_cert_list_all_free(ckmc_cert_list *first);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_CORE_CKMC_TYPE_H */
