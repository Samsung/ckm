/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#pragma once

#include <dpl/noncopyable.h>
#include <dpl/exception.h>
#include <ckm/ckm-type.h>

/*
 * Taken from openssl/ossl_typ.h
 */
struct env_md_ctx_st;
typedef env_md_ctx_st EVP_MD_CTX;
struct env_md_st;
typedef env_md_st EVP_MD;

namespace CKM {

class Digest : public CKM::Noncopyable
{
    public:
        class Exception
        {
            public:
                DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
                DECLARE_EXCEPTION_TYPE(Base, InternalError)
        };
        Digest();
        ~Digest();
        void append(const RawBuffer &data, std::size_t len = 0);
        RawBuffer finalize(void);
        RawBuffer get(void);
        void reset(void);
        unsigned int length(void);

    private:
        EVP_MD_CTX *m_ctx;
        const EVP_MD *m_md;
        RawBuffer m_digest;
        bool m_initialized;
        bool m_finalized;
};

} // namespace CKM

