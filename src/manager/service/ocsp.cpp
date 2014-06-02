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
 * @file        ocsp.cpp
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 * @version     1.0
 * @brief       OCSP implementation.
 */

#include "ocsp.h"
#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <fts.h>
#include <unistd.h>


/* Maximum leeway in validity period: default 5 minutes */
#define MAX_VALIDITY_PERIOD     (5 * 60)

#define CKM_OCSP_OPER_SUCCESS	1
#define CKM_OCSP_OPER_FAIL		0

#define CKM_DEF_STRING_LEN		256

namespace CKM {

OCSPModule::OCSPModule() {
	// Do nothing.
}

OCSPModule::~OCSPModule(){
	// Do nothing.
}

// Loads all system certificates into memory.
int OCSPModule::initailize() {
	systemCerts = loadSystemCerts(CKM_SYSTEM_CERTS_PATH);
	return CKM_OCSP_OPER_SUCCESS;
}


int OCSPModule::verify(const CertificateImplVector &certificateChain) {
	X509 *cert = NULL;
	X509 *issuer = NULL;
	char url[CKM_DEF_STRING_LEN];
	int ocspStatus = -1;
	int result = -1;

	CertificateImplVector::iterator it;
	for(unsigned int i=0; i < certificateChain.size() -1; i++) {// except root certificate
		cert = certificateChain[i].getX509();
		issuer = certificateChain[i+1].getX509();
		extractAIAUrl(cert, url);
		result = ocsp_verify(cert, issuer, systemCerts, url, &ocspStatus);
		if(result != OCSP_STATUS_GOOD) {
			return result;
		}
	}

	return OCSP_STATUS_GOOD;
}


int OCSPModule::ocsp_verify(X509 *cert, X509 *issuer, STACK_OF(X509) *systemCerts, char *url, int *ocspStatus) {
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *bs = NULL;
    OCSP_CERTID *certid = NULL;
    BIO *cbio = NULL;
    SSL_CTX *use_ssl_ctx = NULL;
    char *host = NULL, *port = NULL, *path = NULL;
    ASN1_GENERALIZEDTIME *rev = NULL;
    ASN1_GENERALIZEDTIME *thisupd = NULL;
    ASN1_GENERALIZEDTIME *nextupd = NULL;
    int use_ssl = 0;
    int i,tmpIdx;
    long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
    int ret = 0;
    char subj_buf[256];
    int reason;
//    const char *reason_str = NULL;
    X509_STORE *trustedStore=NULL;

    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl)) {
        /* report error */
        return OCSP_STATUS_INVALID_URL;
    }

    cbio = BIO_new_connect(host);
    if (!cbio) {
        /*BIO_printf(bio_err, "Error creating connect BIO\n");*/
        /* report error */
        return OCSP_STATUS_INTERNAL_ERROR;
    }

    if (port) {
        BIO_set_conn_port(cbio, port);
    }

    if (use_ssl == 1) {
        BIO *sbio;
        use_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        if (!use_ssl_ctx) {
            /* report error */
            return OCSP_STATUS_INTERNAL_ERROR;
        }

        SSL_CTX_set_mode(use_ssl_ctx, SSL_MODE_AUTO_RETRY);
        sbio = BIO_new_ssl(use_ssl_ctx, 1);
        if (!sbio) {
            /* report error */
            return OCSP_STATUS_INTERNAL_ERROR;
        }

        cbio = BIO_push(sbio, cbio);
        if (!cbio) {
            /* report error */
            return OCSP_STATUS_INTERNAL_ERROR;
        }
    }

    if (BIO_do_connect(cbio) <= 0) {
        /*BIO_printf(bio_err, "Error connecting BIO\n");*/
        /* report error */

        /* free stuff */
        if (host)
            OPENSSL_free(host);
        if (port)
            OPENSSL_free(port);
        if (path)
            OPENSSL_free(path);
        host = port = path = NULL;
        if (use_ssl && use_ssl_ctx)
            SSL_CTX_free(use_ssl_ctx);
        use_ssl_ctx = NULL;
        if (cbio)
            BIO_free_all(cbio);
        cbio = NULL;
        return OCSP_STATUS_NET_ERROR;
    }

    req = OCSP_REQUEST_new();

    if(!req) {
        return OCSP_STATUS_INTERNAL_ERROR;
    }
    certid = OCSP_cert_to_id(NULL, cert, issuer);
    if(certid == NULL)  {
    	return OCSP_STATUS_INTERNAL_ERROR;
    }

    if(!OCSP_request_add0_id(req, certid)) {
        return OCSP_STATUS_INTERNAL_ERROR;
    }

    resp = OCSP_sendreq_bio(cbio, path, req);

    /* free some stuff we no longer need */
    if (host)
        OPENSSL_free(host);
    if (port)
        OPENSSL_free(port);
    if (path)
        OPENSSL_free(path);
    host = port = path = NULL;
    if (use_ssl && use_ssl_ctx)
        SSL_CTX_free(use_ssl_ctx);
    use_ssl_ctx = NULL;
    if (cbio)
        BIO_free_all(cbio);
    cbio = NULL;

    if (!resp) {
        /*BIO_printf(bio_err, "Error querying OCSP responsder\n");*/
        /* report error */
        /* free stuff */
        OCSP_REQUEST_free(req);
        return OCSP_STATUS_NET_ERROR;
    }

    i = OCSP_response_status(resp);

    if (i != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        /*BIO_printf(out, "Responder Error: %s (%ld)\n",
                   OCSP_response_status_str(i), i); */
        /* report error */
        /* free stuff */
        OCSP_REQUEST_free(req);
        OCSP_RESPONSE_free(resp);
        return OCSP_STATUS_REMOTE_ERROR;
    }

    bs = OCSP_response_get1_basic(resp);
    if (!bs) {
       /* BIO_printf(bio_err, "Error parsing response\n");*/
        /* report error */
        /* free stuff */
        OCSP_REQUEST_free(req);
        OCSP_RESPONSE_free(resp);
        return OCSP_STATUS_INVALID_RESPONSE;
    }

    if(systemCerts != NULL) {
        trustedStore = X509_STORE_new();
        for(tmpIdx=0; tmpIdx<sk_X509_num(systemCerts); tmpIdx++) {
        	X509_STORE_add_cert(trustedStore, sk_X509_value(systemCerts, tmpIdx));
        }
        X509_STORE_add_cert(trustedStore, issuer);
    }

	int response = OCSP_basic_verify(bs, NULL, trustedStore, 0);
	if (response <= 0) {
		OCSP_REQUEST_free(req);
		OCSP_RESPONSE_free(resp);
		OCSP_BASICRESP_free(bs);
        X509_STORE_free(trustedStore);
        	// 에러 리즌 확인
        int err = ERR_get_error();
        char errStr[100];
        ERR_error_string(err,errStr);
        printf("OCSP_basic_verify fail.error = %s\n", errStr);
		return OCSP_STATUS_INVALID_RESPONSE;
	}


    if ((i = OCSP_check_nonce(req, bs)) <= 0) {
        if (i == -1) {
            /*BIO_printf(bio_err, "WARNING: no nonce in response\n");*/
        } else {
            /*BIO_printf(bio_err, "Nonce Verify error\n");*/
            /* report error */
            /* free stuff */
            OCSP_REQUEST_free(req);
            OCSP_RESPONSE_free(resp);
            OCSP_BASICRESP_free(bs);
            X509_STORE_free(trustedStore);
            return OCSP_STATUS_INVALID_RESPONSE;
        }
    }

    (void)X509_NAME_oneline(X509_get_subject_name(cert), subj_buf, 255);
    if(!OCSP_resp_find_status(bs, certid, ocspStatus, &reason,
                              &rev, &thisupd, &nextupd)) {
        /* report error */

        /* free stuff */
        OCSP_RESPONSE_free(resp);
        OCSP_REQUEST_free(req);
        OCSP_BASICRESP_free(bs);
        X509_STORE_free(trustedStore);

        return OCSP_STATUS_INVALID_RESPONSE;
    }


    /* Check validity: if invalid write to output BIO so we
     * know which response this refers to.
     */
    if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
        /* ERR_print_errors(out); */
        /* report error */

        /* free stuff */
        OCSP_REQUEST_free(req);
        OCSP_RESPONSE_free(resp);
        OCSP_BASICRESP_free(bs);
        X509_STORE_free(trustedStore);

        return OCSP_STATUS_INVALID_RESPONSE;
    }

    if (req != NULL) {
        OCSP_REQUEST_free(req);
        req = NULL;
    }

    if (resp != NULL) {
        OCSP_RESPONSE_free(resp);
        resp = NULL;
    }

    if (bs != NULL) {
        OCSP_BASICRESP_free(bs);
        bs = NULL;
    }

    if(trustedStore != NULL) {
    	X509_STORE_free(trustedStore);
    	trustedStore = NULL;
    }

//    if (reason != -1) {
//        reason_str = OCSP_crl_1reason_str(reason);
//    }
    switch(*ocspStatus) {
    case V_OCSP_CERTSTATUS_GOOD :
    	ret = OCSP_STATUS_GOOD; break;
    case V_OCSP_CERTSTATUS_REVOKED :
    	ret = OCSP_STATUS_REVOKED; break;
    case V_OCSP_CERTSTATUS_UNKNOWN :
    	ret = OCSP_STATUS_UNKNOWN; break;
    }

    return ret;
}


STACK_OF(X509) *OCSPModule::loadSystemCerts( const char * dirpath) {
    FTS *fts = NULL;
    FTSENT *ftsent;
    char tmp[10];
    STACK_OF(X509) *systemCerts = sk_X509_new_null();

    X509 *cert;

    if (NULL == (fts = fts_open((char * const *) &dirpath, FTS_LOGICAL, NULL))) {
    	printf("Fail to open directories. dir=%s \n", dirpath);
    	return NULL;
    }

    while ((ftsent = fts_read(fts)) != NULL) {
        if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
        	printf("Fail to read directories. dir=%s \n", dirpath);
        	fts_close(fts);
   	    	return NULL;
        }

        if (ftsent->fts_info != FTS_F)
            continue;

        if (-1 != readlink(ftsent->fts_path, tmp, 10)) // ignore link file
            continue;

        cert = loadCert(ftsent->fts_path);
        if(cert != NULL) {
        	sk_X509_push(systemCerts, cert);
        }
    }
    if (fts != NULL)
        fts_close(fts);

    return systemCerts;
}


X509 *OCSPModule::loadCert(const char *file) {
	FILE *fp = fopen(file, "r");
	if(fp == NULL)
		return NULL;
	X509 *cert;
	if(!(cert = d2i_X509_fp(fp, NULL))) {
		fseek(fp, 0, SEEK_SET);
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
	}
	fclose(fp);
	return cert;
}

void OCSPModule::extractAIAUrl(X509 *cert, char *url) {
	STACK_OF(OPENSSL_STRING) *aia = NULL;
	aia = X509_get1_ocsp(cert);
	if(aia == NULL) {
		return;
	}
	strcpy(url, sk_OPENSSL_STRING_value(aia, 0));
	X509_email_free(aia);
	return;
}



}
