/*
 *  Central Key Manager
 *
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 */

#ifndef CENT_KEY_MNG_UTIL_H
#define CENT_KEY_MNG_UTIL_H

#include <sys/types.h>
#include <ckm/ckm-type.h>
#include <openssl/x509v3.h>

#define CKM_SYSTEM_CERTS_PATH "/opt/etc/ssl/certs"

namespace CKM {

int util_smack_label_is_valid(const char *smack_label);
char *read_exe_path_from_proc(pid_t pid);

void rawBufferToX509(X509 **ppCert, RawBuffer rawCert);
void x509ToRawBuffer(RawBuffer &buf, X509 *cert);

STACK_OF(X509) *loadSystemCerts( const char * dirpath);
X509 *loadCert(const char *file);

} // namespace CKM

#endif /*CENT_KEY_MNG_UTIL_H*/
