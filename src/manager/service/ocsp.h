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
 * @file        ocsp.h
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 * @version     1.0
 * @brief       OCSP implementation.
 */
#pragma once

#include <openssl/x509v3.h>
#include <ckm/ckm-type.h>
#include <certificate-impl.h>
#include <dpl/exception.h>

namespace CKM {

class OCSPModule {
public:
	OCSPModule();
	virtual ~OCSPModule();

	// all error code from project will be defined in public client api
	// OK, UNKNOWN, REVOKED, NO_NETWORK, TIMEOUT
    int verify(const CertificateImplVector &certificateChain);
private:
    int ocsp_verify(X509 *cert, X509 *issuer, STACK_OF(X509) *systemCerts, const std::string &url);
    STACK_OF(X509) *systemCerts;
};

} // namespace CKM
