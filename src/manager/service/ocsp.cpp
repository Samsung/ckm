/*
 *  Copyright (c) 2014 Samsung Electronics Co.
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

#include <ocsp.h>
#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <fts.h>
#include <unistd.h>
#include <key-manager-util.h>
#include <dpl/log/log.h>

#include <ckm/ckm-error.h>

/* Maximum leeway in validity period: default 5 minutes */
#define MAX_VALIDITY_PERIOD     (5 * 60)

namespace CKM {

OCSPModule::OCSPModule() {
	// Do nothing.
}

OCSPModule::~OCSPModule(){
	// Do nothing.
}

int OCSPModule::verify(const CertificateImplVector &certificateChain) {
    bool unsupported = false; // ocsp is unsupported in certificate in chain (except root CA)

    if((systemCerts = loadSystemCerts(CKM_SYSTEM_CERTS_PATH)) == NULL) {
        LogDebug("Error in loadSystemCerts function");
        return CKM_API_OCSP_STATUS_INTERNAL_ERROR;
    }

    for(unsigned int i=0; i < certificateChain.size() -1; i++) {// except root certificate
        if (certificateChain[i].empty() || certificateChain[i+1].empty()) {
            LogDebug("Error. Broken certificate chain.");
            return CKM_API_OCSP_STATUS_INTERNAL_ERROR;
        }

        X509 *cert   = certificateChain[i].getX509();
        X509 *issuer = certificateChain[i+1].getX509();
        std::string url = certificateChain[i].getOCSPURL();

        if (url.empty()) {
            LogDebug("Certificate does not provide OCSP extension.");
            unsupported = true;
            continue;
        }

        int result = ocsp_verify(cert, issuer, systemCerts, url);

        if(result != CKM_API_OCSP_STATUS_GOOD) {
            LogDebug("Fail to OCSP certification checking: " << result);
            return result;
        }
    }

    if (unsupported)
        return CKM_API_OCSP_STATUS_UNSUPPORTED;
    return CKM_API_OCSP_STATUS_GOOD;
}

int OCSPModule::ocsp_verify(X509 *cert, X509 *issuer, STACK_OF(X509) *systemCerts, const std::string &constUrl) {
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
    int ocspStatus = -1;
	int i = 0 ,tmpIdx = 0;
	long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
	char subj_buf[256];
	int reason = 0;
	//    const char *reason_str = NULL;0
	X509_STORE *trustedStore=NULL;

    std::vector<char> url(constUrl.begin(), constUrl.end());

    if (!OCSP_parse_url(url.data(), &host, &port, &path, &use_ssl)) {
		/* report error */
		return CKM_API_OCSP_STATUS_INVALID_URL;
	}

    cbio = BIO_new_connect(host);
	if (cbio == NULL) {
		/*BIO_printf(bio_err, "Error creating connect BIO\n");*/
		/* report error */
		return CKM_API_OCSP_STATUS_INTERNAL_ERROR;
	}

	if (port != NULL) {
		BIO_set_conn_port(cbio, port);
	}

	if (use_ssl == 1) {
		BIO *sbio = NULL;
		use_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
		if (use_ssl_ctx == NULL) {
			/* report error */
			return CKM_API_OCSP_STATUS_INTERNAL_ERROR;
		}

		SSL_CTX_set_mode(use_ssl_ctx, SSL_MODE_AUTO_RETRY);
		sbio = BIO_new_ssl(use_ssl_ctx, 1);
		if (sbio == NULL) {
			/* report error */
			return CKM_API_OCSP_STATUS_INTERNAL_ERROR;
		}

		cbio = BIO_push(sbio, cbio);
		if (cbio == NULL) {
			/* report error */
			return CKM_API_OCSP_STATUS_INTERNAL_ERROR;
		}
	}

	if (BIO_do_connect(cbio) <= 0) {
		/*BIO_printf(bio_err, "Error connecting BIO\n");*/
		/* report error */

		/* free stuff */
		if (host != NULL) {
			OPENSSL_free(host);
		}

		if (port != NULL) {
			OPENSSL_free(port);
		}

		if (path != NULL) {
			OPENSSL_free(path);
		}
		host = port = path = NULL;

		if (use_ssl && use_ssl_ctx) {
			SSL_CTX_free(use_ssl_ctx);
		}
		use_ssl_ctx = NULL;

		if (cbio != NULL) {
			BIO_free_all(cbio);
		}
		cbio = NULL;

		return CKM_API_OCSP_STATUS_NET_ERROR;
	}

	req = OCSP_REQUEST_new();

	if(req == NULL) {
        LogDebug("Error in OCPS_REQUEST_new");
		return CKM_API_OCSP_STATUS_INTERNAL_ERROR;
	}
	certid = OCSP_cert_to_id(NULL, cert, issuer);
	if(certid == NULL)  {
        LogDebug("Error in OCSP_cert_to_id");
		return CKM_API_OCSP_STATUS_INTERNAL_ERROR;
	}

	if(OCSP_request_add0_id(req, certid) == NULL) {
        LogDebug("Error in OCSP_request_add0_id");
		return CKM_API_OCSP_STATUS_INTERNAL_ERROR;
	}

	resp = OCSP_sendreq_bio(cbio, path, req);

	/* free some stuff we no longer need */
	if (host != NULL) {
		OPENSSL_free(host);
	}

	if (port != NULL) {
		OPENSSL_free(port);
	}

	if (path != NULL) {
		OPENSSL_free(path);
	}
	host = port = path = NULL;

	if (use_ssl && use_ssl_ctx) {
		SSL_CTX_free(use_ssl_ctx);
	}
	use_ssl_ctx = NULL;

	if (cbio != NULL) {
		BIO_free_all(cbio);
	}
	cbio = NULL;

	if (!resp) {
		/*BIO_printf(bio_err, "Error querying OCSP responsder\n");*/
		/* report error */
		/* free stuff */
		OCSP_REQUEST_free(req);
		return CKM_API_OCSP_STATUS_NET_ERROR;
	}

	i = OCSP_response_status(resp);

	if (i != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		/*BIO_printf(out, "Responder Error: %s (%ld)\n",
                   OCSP_response_status_str(i), i); */
		/* report error */
		/* free stuff */
		OCSP_REQUEST_free(req);
		OCSP_RESPONSE_free(resp);
		return CKM_API_OCSP_STATUS_REMOTE_ERROR;
	}

	bs = OCSP_response_get1_basic(resp);
	if (!bs) {
		/* BIO_printf(bio_err, "Error parsing response\n");*/
		/* report error */
		/* free stuff */
		OCSP_REQUEST_free(req);
		OCSP_RESPONSE_free(resp);
		return CKM_API_OCSP_STATUS_INVALID_RESPONSE;
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
		// find the reason of error
		int err = ERR_get_error();
		char errStr[100];
		ERR_error_string(err,errStr);
		// printf("OCSP_basic_verify fail.error = %s\n", errStr);
		return CKM_API_OCSP_STATUS_INVALID_RESPONSE;
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
			return CKM_API_OCSP_STATUS_INVALID_RESPONSE;
		}
	}

	(void)X509_NAME_oneline(X509_get_subject_name(cert), subj_buf, 255);
	if(!OCSP_resp_find_status(bs, certid, &ocspStatus, &reason,
			&rev, &thisupd, &nextupd)) {
		/* report error */

		/* free stuff */
		OCSP_RESPONSE_free(resp);
		OCSP_REQUEST_free(req);
		OCSP_BASICRESP_free(bs);
		X509_STORE_free(trustedStore);

		return CKM_API_OCSP_STATUS_INVALID_RESPONSE;
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

		return CKM_API_OCSP_STATUS_INVALID_RESPONSE;
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

    switch(ocspStatus) {
        case V_OCSP_CERTSTATUS_GOOD:
            return CKM_API_OCSP_STATUS_GOOD;
        case V_OCSP_CERTSTATUS_REVOKED:
            return CKM_API_OCSP_STATUS_REVOKED;
        case V_OCSP_CERTSTATUS_UNKNOWN:
            return CKM_API_OCSP_STATUS_UNKNOWN;
        default:
            LogError("Internal openssl error: Certificate status have value is out of bound.");
            return CKM_API_OCSP_STATUS_INTERNAL_ERROR;
    }
}

} // namespace CKM

