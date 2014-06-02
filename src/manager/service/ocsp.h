#pragma once


#include <openssl/x509v3.h>
#include <vector>


//########################################################
// This is temporary code.
// It should be removed when real CertificateImpl is ready.
namespace CKM {
class CertificateImpl
{
  public:
    explicit CertificateImpl(X509 *cert);
    ~CertificateImpl();
    X509 *getX509(void) const;
  protected:
    X509 *m_x509;
};

CertificateImpl::CertificateImpl(X509 *cert){
    m_x509 = X509_dup(cert);
    if (!m_x509) {
    }
};
X509 *CertificateImpl::getX509(void) const{
	return m_x509;
};

typedef std::vector<CertificateImpl> CertificateImplVector;
} // namespace CKM
//########################################################



#define OCSP_STATUS_GOOD				1
#define OCSP_STATUS_UNKNOWN				2
#define OCSP_STATUS_REVOKED				3
#define OCSP_STATUS_NET_ERROR			4
#define OCSP_STATUS_INVALID_URL			5
#define OCSP_STATUS_INVALID_RESPONSE	6
#define OCSP_STATUS_REMOTE_ERROR		7
#define OCSP_STATUS_INTERNAL_ERROR		8

#define CKM_SYSTEM_CERTS_PATH "/opt/etc/ssl/certs" // or "/usr/share/cert-svc/ca-certs"



namespace CKM {


class OCSPModule {
public:
	OCSPModule();
	virtual ~OCSPModule();

	// Loads all system certificates into memory.
	static int initailize();

	// all error code from project will be defined in public client api
	// OK, UNKNOWN, REVOKED, NO_NETWORK, TIMEOUT
    int verify(const CertificateImplVector &certificateChain);
private:
    int ocsp_verify(X509 *cert, X509 *issuer, STACK_OF(X509) *systemCerts, char *url, int *ocspStatus);
    void extractAIAUrl(X509 *cert, char *url);

    static STACK_OF(X509) *loadSystemCerts( const char * dirpath);
    static X509 *loadCert(const char *file);

    static STACK_OF(X509) *systemCerts;
};

STACK_OF(X509) *OCSPModule::systemCerts;

} // namespace CKM
