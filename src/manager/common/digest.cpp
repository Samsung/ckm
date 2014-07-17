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

#include <dpl/log/log.h>

#include <openssl/evp.h>

#include <digest.h>

namespace CKM {

Digest::Digest() :
    m_digest(EVP_MAX_MD_SIZE)
{
    m_ctx = nullptr;
    m_md = EVP_sha1();
    m_initialized = false;
    m_finalized = false;
}

Digest::~Digest()
{
    EVP_MD_CTX_destroy(m_ctx);
}

void Digest::reset()
{
    int ret = -1;

    if (m_initialized) {
        EVP_MD_CTX_destroy(m_ctx);
        m_ctx = nullptr;
    }

    m_initialized = false;
    m_finalized = false;
    m_ctx = EVP_MD_CTX_create();
    if (m_ctx == nullptr) {
    }

    ret = EVP_DigestInit_ex(m_ctx, m_md, NULL);
    if (ret != 1) {
        ThrowMsg(Exception::InternalError,
                 "Failed to create digest context.");
    }
    m_digest.clear();
    m_digest.resize(EVP_MAX_MD_SIZE);
    m_initialized = true;
}

void Digest::append(const SafeBuffer &data, std::size_t len)
{
    int ret = -1;

    if (data.size() == 0) {
        ThrowMsg(Exception::InternalError, "Empty data.");
    }
    if (0 == len)
        len = data.size();
    if (m_finalized) {
        ThrowMsg(Exception::InternalError, "Already finalized.");
    }
    if (not m_initialized)
        reset();
    ret = EVP_DigestUpdate(m_ctx, data.data(), len);
    if (ret != 1) {
        ThrowMsg(Exception::InternalError,
                 "Failed to calculate digest in openssl.");
    }
}

SafeBuffer Digest::finalize()
{
    int ret = -1;
    unsigned int dlen;

    if (m_finalized) {
        ThrowMsg(Exception::InternalError, "Already finalized.");
    }
    m_finalized = true;
    ret = EVP_DigestFinal_ex(m_ctx, m_digest.data(), &dlen);
    if (ret != 1) {
        ThrowMsg(Exception::InternalError,
                 "Failed in digest final in openssl.");
    }
    if (dlen != length()) {
        ThrowMsg(Exception::InternalError, "Invalid digest length.");
    }
    if (dlen != EVP_MAX_MD_SIZE)
        m_digest.resize(dlen);
    return m_digest;
}

SafeBuffer Digest::get()
{
    if (m_finalized)
        return m_digest;
    else
        return SafeBuffer();
}

unsigned int Digest::length()
{
    return m_md->md_size;
}

} // namespace CKM

