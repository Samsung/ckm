/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
#ifndef _BASE64_H_
#define _BASE64_H_

#include <string>
#include <dpl/noncopyable.h>
#include <dpl/exception.h>

#include <ckm/ckm-type.h>

struct bio_st;
typedef bio_st BIO;

namespace CKM {

class Base64Encoder : public CKM::Noncopyable
{
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, InternalError)
        DECLARE_EXCEPTION_TYPE(Base, NotFinalized)
        DECLARE_EXCEPTION_TYPE(Base, AlreadyFinalized)
    };
    Base64Encoder();
    void append(const RawBuffer &data);
    void finalize();
    RawBuffer get();
    void reset();
    ~Base64Encoder();

  private:
    BIO *m_b64;
    BIO *m_bmem;
    bool m_finalized;
};

class Base64Decoder : public CKM::Noncopyable
{
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, InternalError)
        DECLARE_EXCEPTION_TYPE(Base, NotFinalized)
        DECLARE_EXCEPTION_TYPE(Base, AlreadyFinalized)
    };
    Base64Decoder();
    void append(const RawBuffer &data);

    /*
     *  Function will return false when BIO_read fails
     *  (for example: when string was not in base64 format).
     */
    bool finalize();
    RawBuffer get() const;
    void reset();
    ~Base64Decoder()
    {
    }

  private:
    RawBuffer m_input;
    RawBuffer m_output;
    bool m_finalized;
};
} // namespace CKM

#endif
