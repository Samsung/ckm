/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 */
/*
 * @file       openssl_utils.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <openssl/x509.h>

#include <memory>

namespace CKM
{

typedef std::unique_ptr<X509_STORE_CTX, void(*)(X509_STORE_CTX*)> X509_STORE_CTX_PTR;
typedef std::unique_ptr<STACK_OF(X509), void(*)(STACK_OF(X509)*)> X509_STACK_PTR;

inline X509_STACK_PTR create_x509_stack()
{
    return X509_STACK_PTR(sk_X509_new_null(), [](STACK_OF(X509)* stack) { sk_X509_free(stack); });
}
inline X509_STORE_CTX_PTR create_x509_store_ctx()
{
    return X509_STORE_CTX_PTR(X509_STORE_CTX_new(), X509_STORE_CTX_free);
}

} // namespace CKM

