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
 * @file        ckmc-type.cpp
 * @author      Yuseok Jeon(yuseok.jeon@samsung.com)
 * @version     1.0
 * @brief       new and free methods for the struct of CAPI
 */


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ckm/ckm-type.h>
#include <ckmc/ckmc-type.h>
#include <ckmc/ckmc-error.h>
#include <ckmc-type-converter.h>
#include <protocols.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <fstream>
#include <crypto-init.h>

namespace {

const size_t DEFAULT_IV_LEN = 16;
const size_t DEFAULT_IV_LEN_BITS = 8*DEFAULT_IV_LEN;
const size_t DEFAULT_KEY_LEN_BITS = 4096;

int _ckmc_load_cert_from_x509(X509 *xCert, ckmc_cert_s **cert)
{
    if(xCert == NULL) {
        return CKMC_ERROR_INVALID_FORMAT;
    }

    BIO *bcert = BIO_new(BIO_s_mem());

    i2d_X509_bio(bcert, xCert);

    CKM::RawBuffer output(8196);
    int size = BIO_read(bcert, output.data(), output.size());
    BIO_free_all(bcert);
    if (size <= 0) {
        return CKMC_ERROR_INVALID_FORMAT;
    }
    output.resize(size);

    return ckmc_cert_new(output.data(), output.size(), CKMC_FORM_DER, cert);
}

} // namespace anonymous


const char * const ckmc_label_name_separator    = CKM::LABEL_NAME_SEPARATOR;
const char * const ckmc_owner_id_separator      = CKM::LABEL_NAME_SEPARATOR;
const char * const ckmc_owner_id_system         = CKM::OWNER_ID_SYSTEM;

KEY_MANAGER_CAPI
int ckmc_key_new(unsigned char *raw_key, size_t key_size, ckmc_key_type_e key_type, char *password, ckmc_key_s **ppkey)
{
    ckmc_key_s *pkey;

    if(raw_key == NULL || key_size == 0 || ppkey == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    pkey = static_cast<ckmc_key_s*>(malloc(sizeof(ckmc_key_s)));
    if(pkey == NULL) {
        return CKMC_ERROR_OUT_OF_MEMORY;
    }
    pkey->raw_key = reinterpret_cast<unsigned char*>(malloc(key_size));
    if(pkey->raw_key == NULL) {
        free(pkey);
        return CKMC_ERROR_OUT_OF_MEMORY;
    }
    memcpy(pkey->raw_key, raw_key, key_size);

    pkey->key_size = key_size;
    pkey->key_type = key_type;

    if(password != NULL) {
        pkey->password = reinterpret_cast<char*>(malloc(strlen(password) +1));
        if(pkey->password == NULL) {
            free(pkey->raw_key);
            free(pkey);
            return CKMC_ERROR_OUT_OF_MEMORY;
        }
        memset(pkey->password, 0, strlen(password) +1);
        strncpy(pkey->password, password, strlen(password));
    }else {
        pkey->password = NULL;
    }

    *ppkey = pkey;

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
void ckmc_key_free(ckmc_key_s *key)
{
    if(key == NULL)
        return;

    if(key->password != NULL)
        free(key->password);
    if(key->raw_key != NULL) {
        memset(key->raw_key, 0, key->key_size);
        free(key->raw_key);
    }

    free(key);
}

KEY_MANAGER_CAPI
int ckmc_buffer_new(unsigned char *data, size_t size,ckmc_raw_buffer_s **ppbuffer)
{
    ckmc_raw_buffer_s *pbuff;

    if(data == NULL || size == 0 || ppbuffer == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    pbuff = static_cast<ckmc_raw_buffer_s*>(malloc(sizeof(ckmc_raw_buffer_s)));
    if(pbuff == NULL)
            return CKMC_ERROR_OUT_OF_MEMORY;

    pbuff->data = reinterpret_cast<unsigned char*>(malloc(size));
    if(pbuff->data == NULL) {
        free(pbuff);
        return CKMC_ERROR_OUT_OF_MEMORY;
    }
    memcpy(pbuff->data, data, size);

    pbuff->size = size;
    *ppbuffer = pbuff;

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
void ckmc_buffer_free(ckmc_raw_buffer_s *buffer)
{
    if(buffer == NULL)
        return;

    if(buffer->data != NULL) {
        memset(buffer->data, 0, buffer->size);
        free(buffer->data);
    }
    free(buffer);
}

KEY_MANAGER_CAPI
int ckmc_cert_new(unsigned char *raw_cert, size_t cert_size, ckmc_data_format_e data_format, ckmc_cert_s **ppcert)
{
    ckmc_cert_s *pcert;

    if(raw_cert == NULL || cert_size == 0 || ppcert == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    pcert = static_cast<ckmc_cert_s*>(malloc(sizeof(ckmc_cert_s)));
    if(pcert == NULL) {
        return CKMC_ERROR_OUT_OF_MEMORY;
    }
    pcert->raw_cert = reinterpret_cast<unsigned char*>(malloc(cert_size));
    if(pcert->raw_cert == NULL) {
        free(pcert);
        return CKMC_ERROR_OUT_OF_MEMORY;
    }
    memcpy(pcert->raw_cert, raw_cert, cert_size);

    pcert->cert_size = cert_size;
    pcert->data_format = data_format;

    *ppcert = pcert;
    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_load_cert_from_file(const char *file_path, ckmc_cert_s **cert)
{
    CKM::initOpenSslOnce();

    FILE *fp = fopen(file_path, "r");
    if(fp == NULL)
        return CKMC_ERROR_FILE_ACCESS_DENIED;
    X509 *pcert = NULL;
    if(!(pcert = d2i_X509_fp(fp, NULL))) {
        fseek(fp, 0, SEEK_SET);
        pcert = PEM_read_X509(fp, NULL, NULL, NULL);
    }
    fclose(fp);
    if(pcert == NULL) {
        return CKMC_ERROR_INVALID_FORMAT;
    }

    int ret = _ckmc_load_cert_from_x509(pcert, cert);
    if(ret != CKMC_ERROR_NONE) {
        X509_free(pcert);
    }
    return ret;
}

KEY_MANAGER_CAPI
void ckmc_cert_free(ckmc_cert_s *cert)
{
    if(cert == NULL)
        return;

    if(cert->raw_cert != NULL) {
        memset(cert->raw_cert, 0, cert->cert_size);
        free(cert->raw_cert);
    }
    free(cert);
}

KEY_MANAGER_CAPI
int ckmc_pkcs12_new(ckmc_key_s *private_key, ckmc_cert_s *cert,
        ckmc_cert_list_s *ca_cert_list, ckmc_pkcs12_s **pkcs12_bundle)
{
    ckmc_pkcs12_s *pkcs12;

    if(!pkcs12_bundle ||
       (private_key==NULL && cert==NULL && (ca_cert_list==NULL || ca_cert_list->cert==NULL))) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    pkcs12 = static_cast<ckmc_pkcs12_s*>(malloc(sizeof(ckmc_pkcs12_s)));
    if(pkcs12 == NULL) {
        return CKMC_ERROR_OUT_OF_MEMORY;
    }
    // ownership is transferred into pkcs12 - mentioned in the docs
    pkcs12->priv_key = private_key;
    pkcs12->cert = cert;
    pkcs12->ca_chain = ca_cert_list;

    *pkcs12_bundle = pkcs12;
    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_load_from_pkcs12_file(const char *file_path, const char *passphrase, ckmc_key_s **private_key, ckmc_cert_s **ckmcert, ckmc_cert_list_s **ca_cert_list)
{
    class Pkcs12Converter {
    private:
        FILE* fp_in;
        PKCS12* p12;
        EVP_PKEY* pkey;
        X509* x509Cert;
        STACK_OF(X509)* ca;

        int ret;
    public:
        ckmc_key_s *retPrivateKey;
        ckmc_cert_s *retCkmCert;
        ckmc_cert_list_s *retCaCertList;

        Pkcs12Converter(){
            fp_in = NULL;
            p12 = NULL;
            pkey = NULL;
            x509Cert = NULL;
            ca = NULL;
            ret = CKMC_ERROR_NONE;
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

            if(ret != CKMC_ERROR_NONE) {
                if(retPrivateKey != NULL){
                    ckmc_key_free(retPrivateKey);
                    retPrivateKey = NULL;
                }
                if(retCkmCert != NULL) {
                    ckmc_cert_free(retCkmCert);
                    retCkmCert = NULL;
                }
                if(retCaCertList != NULL) {
                    ckmc_cert_list_all_free(retCaCertList);
                    retCaCertList = NULL;
                }
            }
        };

        int parsePkcs12(const char *filePath, const char *pass) {
            fp_in = NULL;
            if(!(fp_in = fopen(filePath, "rb"))) {
                return CKMC_ERROR_FILE_ACCESS_DENIED;
            }

            if(!(p12 = d2i_PKCS12_fp(fp_in, NULL))) {
                return CKMC_ERROR_INVALID_FORMAT;
            }

            /* parse PKCS#12 certificate */
            if((ret = PKCS12_parse(p12, pass, &pkey, &x509Cert, &ca)) != 1) {
                return CKMC_ERROR_INVALID_FORMAT;
            }
            return CKMC_ERROR_NONE;
        }

        int toCkmCert() {
            if( (ret =_ckmc_load_cert_from_x509(x509Cert,&retCkmCert)) != CKMC_ERROR_NONE) {
                return ret;
            }
            return CKMC_ERROR_NONE;
        }

        int toCkmKey() {
            BIO *bkey = BIO_new(BIO_s_mem());

            i2d_PrivateKey_bio(bkey, pkey);

            CKM::RawBuffer output(8196);
            int size = BIO_read(bkey, output.data(), output.size());
            BIO_free_all(bkey);
            if (size <= 0) {
                return CKMC_ERROR_INVALID_FORMAT;
            }
            output.resize(size);

            int type = EVP_PKEY_type(pkey->type);
            ckmc_key_type_e key_type = CKMC_KEY_NONE;
            switch(type) {
            case EVP_PKEY_RSA :
                key_type = CKMC_KEY_RSA_PRIVATE;
                break;
            case EVP_PKEY_DSA :
                key_type = CKMC_KEY_DSA_PRIVATE;
                break;
            case EVP_PKEY_EC :
                key_type = CKMC_KEY_ECDSA_PRIVATE;
                break;
            }
            if(key_type == CKMC_KEY_NONE) {
                return CKMC_ERROR_INVALID_FORMAT;
            }

            char *nullPassword = NULL;

            return ckmc_key_new(output.data(), size, key_type, nullPassword, &retPrivateKey);
        }

        int toCaCkmCertList() {
            int tmpRet;
            X509* popedCert = NULL;
            ckmc_cert_s *popedCkmCert = NULL;
            ckmc_cert_list_s *tmpCertList = NULL;
            while((popedCert = sk_X509_pop(ca)) != NULL) {
                if( (tmpRet =_ckmc_load_cert_from_x509(popedCert, &popedCkmCert)) != CKMC_ERROR_NONE) {
                    return CKMC_ERROR_OUT_OF_MEMORY;
                }
                if(tmpCertList == NULL) { // first
                    tmpRet = ckmc_cert_list_new(popedCkmCert, &tmpCertList);
                    retCaCertList = tmpCertList;
                }else {
                    tmpRet = ckmc_cert_list_add(tmpCertList, popedCkmCert, &tmpCertList);
                }
                if(tmpRet != CKMC_ERROR_NONE) {
                    ckmc_cert_list_all_free(retCaCertList);
                    retCaCertList = NULL;
                    return tmpRet;
                }
            }
            return CKMC_ERROR_NONE;
        }

    };

    CKM::initOpenSslOnce();

    int ret = CKMC_ERROR_NONE;

    Pkcs12Converter converter;
    if((ret = converter.parsePkcs12(file_path, passphrase)) != CKMC_ERROR_NONE) {
        return ret;
    }
    if((ret = converter.toCkmCert()) != CKMC_ERROR_NONE) {
        return ret;
    }
    if((ret = converter.toCkmKey()) != CKMC_ERROR_NONE) {
        return ret;
    }
    if((ret = converter.toCaCkmCertList()) != CKMC_ERROR_NONE) {
        return ret;
    }

    *private_key = converter.retPrivateKey;
    *ckmcert = converter.retCkmCert;
    *ca_cert_list = converter.retCaCertList;

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_pkcs12_load(const char *file_path, const char *passphrase, ckmc_pkcs12_s **pkcs12_bundle)
{
    int ec;
    ckmc_key_s *private_key = 0;
    ckmc_cert_s *cert = 0;
    ckmc_cert_list_s *ca_cert_list = 0;

    if(!file_path || !pkcs12_bundle)
        return CKMC_ERROR_INVALID_PARAMETER;

    ec = ckmc_load_from_pkcs12_file(file_path, passphrase, &private_key, &cert, &ca_cert_list);
    if(ec != CKMC_ERROR_NONE)
        return ec;

    ec = ckmc_pkcs12_new(private_key, cert, ca_cert_list, pkcs12_bundle);
    if(ec != CKMC_ERROR_NONE)
    {
        ckmc_key_free(private_key);
        ckmc_cert_free(cert);
        ckmc_cert_list_free(ca_cert_list);
        return ec;
    }

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
void ckmc_pkcs12_free(ckmc_pkcs12_s *pkcs12)
{
    if(pkcs12 == NULL)
        return;

    ckmc_key_free(pkcs12->priv_key);
    ckmc_cert_free(pkcs12->cert);
    ckmc_cert_list_free(pkcs12->ca_chain);
    free(pkcs12);
}

KEY_MANAGER_CAPI
int ckmc_alias_list_new(char *alias, ckmc_alias_list_s **ppalias_list)
{
    ckmc_alias_list_s *previous = NULL;
    return ckmc_alias_list_add(previous, alias, ppalias_list);
}

KEY_MANAGER_CAPI
int ckmc_alias_list_add(ckmc_alias_list_s *previous, char *alias, ckmc_alias_list_s **pplast)
{
    ckmc_alias_list_s *plist;

    if(alias == NULL || pplast == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    plist = static_cast<ckmc_alias_list_s*>(malloc(sizeof(ckmc_alias_list_s)));
    if(plist == NULL) {
        return CKMC_ERROR_OUT_OF_MEMORY;
    }

    plist->alias = alias;
    plist->next = NULL;

    if(previous != NULL) {
        previous->next = plist;
    }
    *pplast = plist;

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
void ckmc_alias_list_free(ckmc_alias_list_s *first)
{
    ckmc_alias_list_s *next = first;
    while (next) {
        ckmc_alias_list_s *current = next;
        next = current->next;
        free(current);
    }
}

KEY_MANAGER_CAPI
void ckmc_alias_list_all_free(ckmc_alias_list_s *first)
{
    ckmc_alias_list_s *next = first;
    while (next) {
        ckmc_alias_list_s *current = next;
        next = current->next;
        free(current->alias);
        free(current);
    }
}

KEY_MANAGER_CAPI
int ckmc_cert_list_new(ckmc_cert_s *cert, ckmc_cert_list_s **ppalias_list)
{
    ckmc_cert_list_s *previous = NULL;
    return ckmc_cert_list_add(previous, cert, ppalias_list);
}

KEY_MANAGER_CAPI
int ckmc_cert_list_add(ckmc_cert_list_s *previous, ckmc_cert_s *cert, ckmc_cert_list_s **pplast)
{
    ckmc_cert_list_s *plist;

    if(cert == NULL || pplast == NULL) {
        return CKMC_ERROR_INVALID_PARAMETER;
    }

    plist = static_cast<ckmc_cert_list_s*>(malloc(sizeof(ckmc_cert_list_s)));
    if(plist == NULL) {
        return CKMC_ERROR_OUT_OF_MEMORY;
    }
    plist->cert = cert;
    plist->next = NULL;

    if(previous != NULL) {
        previous->next = plist;
    }

    *pplast = plist;

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
void ckmc_cert_list_free(ckmc_cert_list_s *first)
{
    ckmc_cert_list_s *next = first;
    while (next) {
        ckmc_cert_list_s *current = next;
        next = current->next;
        free(current);
    }
}

KEY_MANAGER_CAPI
void ckmc_cert_list_all_free(ckmc_cert_list_s *first)
{
    ckmc_cert_list_s *next = first;
    while (next) {
        ckmc_cert_list_s *current = next;
        next = current->next;
        ckmc_cert_free(current->cert);
        free(current);
    }
}

KEY_MANAGER_CAPI
int ckmc_param_list_new(ckmc_param_list_h *pparams)
{
    if (!pparams)
        return CKMC_ERROR_INVALID_PARAMETER;

    *pparams = reinterpret_cast<ckmc_param_list_h>(new(std::nothrow)(CKM::CryptoAlgorithm));
    if (!*pparams)
        return CKMC_ERROR_OUT_OF_MEMORY;
    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_param_list_set_integer(ckmc_param_list_h params,
                                ckmc_param_name_e name,
                                uint64_t value)
{
    if (!params)
        return CKMC_ERROR_INVALID_PARAMETER;

    CKM::CryptoAlgorithm* algo = reinterpret_cast<CKM::CryptoAlgorithm*>(params);
    bool ret = algo->setParam(static_cast<CKM::ParamName>(name), value);
    return (ret ? CKMC_ERROR_NONE : CKMC_ERROR_INVALID_PARAMETER);
}

KEY_MANAGER_CAPI
int ckmc_param_list_set_buffer(ckmc_param_list_h params,
                               ckmc_param_name_e name,
                               const ckmc_raw_buffer_s *buffer)
{
    if (!params || !buffer || !buffer->data || buffer->size == 0)
        return CKMC_ERROR_INVALID_PARAMETER;

    CKM::CryptoAlgorithm* algo = reinterpret_cast<CKM::CryptoAlgorithm*>(params);
    CKM::RawBuffer b(buffer->data, buffer->data + buffer->size);
    bool ret =  algo->setParam(static_cast<CKM::ParamName>(name), b);
    return (ret ? CKMC_ERROR_NONE : CKMC_ERROR_INVALID_PARAMETER);
}

KEY_MANAGER_CAPI
int ckmc_param_list_get_integer(ckmc_param_list_h params,
                                ckmc_param_name_e name,
                                uint64_t *pvalue)
{
    if (!params || !pvalue)
        return CKMC_ERROR_INVALID_PARAMETER;

    const CKM::CryptoAlgorithm* algo = reinterpret_cast<const CKM::CryptoAlgorithm*>(params);
    if (!algo->getParam(static_cast<CKM::ParamName>(name), *pvalue))
        return CKMC_ERROR_INVALID_PARAMETER;

    return CKMC_ERROR_NONE;
}

KEY_MANAGER_CAPI
int ckmc_param_list_get_buffer(ckmc_param_list_h params,
                               ckmc_param_name_e name,
                               ckmc_raw_buffer_s **ppbuffer)
{
    if (!params || !ppbuffer || *ppbuffer)
        return CKMC_ERROR_INVALID_PARAMETER;

    const CKM::CryptoAlgorithm* algo = reinterpret_cast<const CKM::CryptoAlgorithm*>(params);
    CKM::RawBuffer value;
    if (!algo->getParam(static_cast<CKM::ParamName>(name),value))
        return CKMC_ERROR_INVALID_PARAMETER;

    return ckmc_buffer_new(value.data(), value.size(), ppbuffer);
}

KEY_MANAGER_CAPI
void ckmc_param_list_free(ckmc_param_list_h params)
{
    CKM::CryptoAlgorithm* algo = reinterpret_cast<CKM::CryptoAlgorithm*>(params);
    delete algo;
}

KEY_MANAGER_CAPI
int ckmc_generate_new_params(ckmc_algo_type_e type, ckmc_param_list_h *pparams)
{
    if (!pparams)
        return CKMC_ERROR_INVALID_PARAMETER;

    ckmc_param_list_h params = NULL;
    int ret = ckmc_param_list_new(&params);
    if (ret != CKMC_ERROR_NONE)
        return ret;

    switch (type) {
    case CKMC_ALGO_AES_CTR:
        ret = ckmc_param_list_set_integer(params, CKMC_PARAM_ED_CTR_LEN, DEFAULT_IV_LEN_BITS);
        break;
    case CKMC_ALGO_AES_CBC:
    case CKMC_ALGO_AES_GCM:
    case CKMC_ALGO_AES_CFB:
    case CKMC_ALGO_RSA_OAEP:
        // no iv by default
        break;
    default:
        ret = CKMC_ERROR_INVALID_PARAMETER;
        break;
    }

    if (ret != CKMC_ERROR_NONE) {
        ckmc_param_list_free(params);
        return ret;
    }

    ret = ckmc_param_list_set_integer(params, CKMC_PARAM_ALGO_TYPE, type);
    if (ret != CKMC_ERROR_NONE) {
        ckmc_param_list_free(params);
        return ret;
    }

    *pparams = params;

    return CKMC_ERROR_NONE;
}
