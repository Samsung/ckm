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
 * @file        ocsp-logic.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       OCSP logic implementation.
 */

#include <vector>
#include <string>

#include <system_info.h>

#include <ckm/ckm-error.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <message-buffer.h>

#include <ocsp-logic.h>
#include <ocsp.h>

namespace {

const std::vector<std::string> FEATURES = {
    "tizen.org/feature/network.internet",
    "tizen.org/feature/network.telephony",
    "tizen.org/feature/network.tethering.bluetooth",
    "tizen.org/feature/network.ethernet"};

} // namespace anonymous

namespace CKM {

OCSPLogic::OCSPLogic() : m_isNetAvailable(false)
{
    setNetAvailable();
}

void OCSPLogic::setNetAvailable()
{
    bool value;
    int ret;

    for (const auto &feature : FEATURES) {
        value = false;

        ret = system_info_get_platform_bool(feature.c_str(), &value);
        if (ret != SYSTEM_INFO_ERROR_NONE) {
            LogError("Error in system_info_get_platform_bool. ret : " << ret);
            continue;
        }

        if (value) {
            m_isNetAvailable = true;
            return;
        }
    }

    m_isNetAvailable = false;
}

RawBuffer OCSPLogic::ocspCheck(int commandId, const RawBufferVector &rawChain) {
    CertificateImplVector certChain;
    OCSPModule ocsp;
    int retCode = CKM_API_SUCCESS;
    int ocspStatus = CKM_API_OCSP_STATUS_INTERNAL_ERROR;

    if (!m_isNetAvailable) {
        /* try again for in case of system-info error */
        setNetAvailable();
    }

    if (!m_isNetAvailable) {
        retCode = CKM_API_ERROR_NOT_SUPPORTED;
    } else {
        if (rawChain.size() < 2) {
            LogError("Certificate chain should contain at least 2 certificates");
            retCode = CKM_API_ERROR_INPUT_PARAM;
        } else {
            for (auto &e: rawChain) {
                certChain.push_back(CertificateImpl(e, DataFormat::FORM_DER));
                if (certChain.rbegin()->empty()) {
                    LogDebug("Error in parsing certificates!");
                    retCode = CKM_API_ERROR_INPUT_PARAM;
                    break;
                }
            }
        }
    }

    if (retCode == CKM_API_SUCCESS)
        ocspStatus = ocsp.verify(certChain);

    return MessageBuffer::Serialize(commandId, retCode, ocspStatus).Pop();
}

} // namespace CKM

