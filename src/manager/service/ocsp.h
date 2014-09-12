#pragma once


#include <openssl/x509v3.h>
#include <ckm/ckm-type.h>
#include <certificate-impl.h>
#include <dpl/exception.h>

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

    class Exception {
    	public:
    	    DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
    		DECLARE_EXCEPTION_TYPE(Base, OCSP_Internal);
       		DECLARE_EXCEPTION_TYPE(Base, Openssl_Error);
    };

	// all error code from project will be defined in public client api
	// OK, UNKNOWN, REVOKED, NO_NETWORK, TIMEOUT
    int verify(const CertificateImplVector &certificateChain);
private:
    int ocsp_verify(X509 *cert, X509 *issuer, STACK_OF(X509) *systemCerts, char *url, int *ocspStatus);
    void extractAIAUrl(X509 *cert, char *url);
    STACK_OF(X509) *systemCerts;

};

} // namespace CKM
