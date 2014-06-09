#pragma once


#include <openssl/x509v3.h>
#include <ckm/ckm-type.h>
#include <certificate-impl.h>


#define OCSP_STATUS_GOOD				1
#define OCSP_STATUS_UNKNOWN				2
#define OCSP_STATUS_REVOKED				3
#define OCSP_STATUS_NET_ERROR			4
#define OCSP_STATUS_INVALID_URL			5
#define OCSP_STATUS_INVALID_RESPONSE	6
#define OCSP_STATUS_REMOTE_ERROR		7
#define OCSP_STATUS_INTERNAL_ERROR		8


namespace CKM {


class OCSPModule {
public:
	OCSPModule();
	virtual ~OCSPModule();

	// Loads all system certificates into memory.
	static int initialize();

	// all error code from project will be defined in public client api
	// OK, UNKNOWN, REVOKED, NO_NETWORK, TIMEOUT
    int verify(const CertificateImplVector &certificateChain);
private:
    int ocsp_verify(X509 *cert, X509 *issuer, STACK_OF(X509) *systemCerts, char *url, int *ocspStatus);
    void extractAIAUrl(X509 *cert, char *url);
    static STACK_OF(X509) *systemCerts;

};

STACK_OF(X509) *OCSPModule::systemCerts;

} // namespace CKM
