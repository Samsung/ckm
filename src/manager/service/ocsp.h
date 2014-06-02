#pragma once

namespace CKM {

class CertifiateImpl; // this class will be taken from vcore (vcore::Certificate)
typedef std::vector<CertificateImpl> CertificateImplVector;

class OCSPModule {
public:
	// all error code from project will be defined in public client api
	// OK, UNKNOWN, REVOKED, NO_NETWORK, TIMEOUT
    int verify(const CertificateImplVector &certificateChain);
private:

};

} // namespace CKM