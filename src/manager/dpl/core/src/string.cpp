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
/*
 * @file        string.cpp
 * @author      Piotr Marcinkiewicz (p.marcinkiew@samsung.com)
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 */
#include <stddef.h>
#include <memory>
#include <dpl/string.h>
#include <dpl/char_traits.h>
#include <dpl/errno_string.h>
#include <dpl/exception.h>
#include <dpl/log/log.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <errno.h>
#include <iconv.h>
#include <unicode/ustring.h>

// TODO: Completely move to ICU
namespace CKM {
namespace //anonymous
{
class ASCIIValidator
{
    const std::string& m_TestedString;

  public:
    ASCIIValidator(const std::string& aTestedString);

    void operator()(char aCharacter) const;
};

ASCIIValidator::ASCIIValidator(const std::string& aTestedString) :
    m_TestedString(aTestedString)
{}

void ASCIIValidator::operator()(char aCharacter) const
{
    // Check for ASCII data range
    if (aCharacter <= 0) {
        ThrowMsg(
            StringException::InvalidASCIICharacter,
            "invalid character code " << static_cast<int>(aCharacter)
                                      << " from string [" <<
            m_TestedString
                                      << "] passed as ASCII");
    }
}

const iconv_t gc_IconvOperError = reinterpret_cast<iconv_t>(-1);
const size_t gc_IconvConvertError = static_cast<size_t>(-1);
} // namespace anonymous

String FromUTF8String(const std::string& aIn)
{
    if (aIn.empty()) {
        return String();
    }

    size_t inbytes = aIn.size();

    // Default iconv UTF-32 module adds BOM (4 bytes) in from of string
    // The worst case is when 8bit UTF-8 char converts to 32bit UTF-32
    // newsize = oldsize * 4 + end + bom
    // newsize - bytes for UTF-32 string
    // oldsize - letters in UTF-8 string
    // end - end character for UTF-32 (\0)
    // bom - Unicode header in front of string (0xfeff)
    size_t outbytes = sizeof(wchar_t) * (inbytes + 2);
    std::vector<wchar_t> output(inbytes + 2, 0);

    size_t outbytesleft = outbytes;
    char* inbuf = const_cast<char*>(aIn.c_str());

    // vector is used to provide buffer for iconv which expects char* buffer
    // but during conversion from UTF32 uses internaly wchar_t
    char* outbuf = reinterpret_cast<char*>(&output[0]);

    iconv_t iconvHandle = iconv_open("UTF-32", "UTF-8");

    if (gc_IconvOperError == iconvHandle) {
        int error = errno;

        ThrowMsg(StringException::IconvInitErrorUTF8ToUTF32,
                 "iconv_open failed for " << "UTF-32 <- UTF-8" <<
                 "error: " << GetErrnoString(error));
    }

    size_t iconvRet = iconv(iconvHandle,
                            &inbuf,
                            &inbytes,
                            &outbuf,
                            &outbytesleft);

    iconv_close(iconvHandle);

    if (gc_IconvConvertError == iconvRet) {
        ThrowMsg(StringException::IconvConvertErrorUTF8ToUTF32,
                 "iconv failed for " << "UTF-32 <- UTF-8" << "error: "
                                     << GetErrnoString());
    }

    // Ignore BOM in front of UTF-32
    return &output[1];
}

std::string ToUTF8String(const CKM::String& aIn)
{
    if (aIn.empty()) {
        return std::string();
    }

    size_t inbytes = aIn.size() * sizeof(wchar_t);
    size_t outbytes = inbytes + sizeof(char);

    // wstring returns wchar_t but iconv expects char*
    // iconv internally is processing input as wchar_t
    char* inbuf = reinterpret_cast<char*>(const_cast<wchar_t*>(aIn.c_str()));
    std::vector<char> output(inbytes, 0);
    char* outbuf = &output[0];

    size_t outbytesleft = outbytes;

    iconv_t iconvHandle = iconv_open("UTF-8", "UTF-32");

    if (gc_IconvOperError == iconvHandle) {
        ThrowMsg(StringException::IconvInitErrorUTF32ToUTF8,
                 "iconv_open failed for " << "UTF-8 <- UTF-32"
                                          << "error: " << GetErrnoString());
    }

    size_t iconvRet = iconv(iconvHandle,
                            &inbuf,
                            &inbytes,
                            &outbuf,
                            &outbytesleft);

    iconv_close(iconvHandle);

    if (gc_IconvConvertError == iconvRet) {
        ThrowMsg(StringException::IconvConvertErrorUTF32ToUTF8,
                 "iconv failed for " << "UTF-8 <- UTF-32"
                                     << "error: " << GetErrnoString());
    }

    return &output[0];
}

String FromASCIIString(const std::string& aString)
{
    String output;

    std::for_each(aString.begin(), aString.end(), ASCIIValidator(aString));
    std::copy(aString.begin(), aString.end(), std::back_inserter<String>(output));

    return output;
}

String FromUTF32String(const std::wstring& aString)
{
    return String(&aString[0]);
}

static UChar *ConvertToICU(const String &inputString)
{
    std::unique_ptr<UChar[]> outputString;
    int32_t size = 0;
    int32_t convertedSize = 0;
    UErrorCode error = U_ZERO_ERROR;

    // Calculate size of output string
    ::u_strFromWCS(NULL,
                   0,
                   &size,
                   inputString.c_str(),
                   -1,
                   &error);

    if (error == U_ZERO_ERROR ||
        error == U_BUFFER_OVERFLOW_ERROR)
    {
        // What buffer size is ok ?
        LogPedantic("ICU: Output buffer size: " << size);
    } else {
        ThrowMsg(StringException::ICUInvalidCharacterFound,
                 "ICU: Failed to retrieve output string size. Error: "
                 << error);
    }

    // Allocate proper buffer
    outputString.reset(new UChar[size + 1]);
    ::memset(outputString.get(), 0, sizeof(UChar) * (size + 1));

    error = U_ZERO_ERROR;

    // Do conversion
    ::u_strFromWCS(outputString.get(),
                   size + 1,
                   &convertedSize,
                   inputString.c_str(),
                   -1,
                   &error);

    if (!U_SUCCESS(error)) {
        ThrowMsg(StringException::ICUInvalidCharacterFound,
                 "ICU: Failed to convert string. Error: " << error);
    }

    // Done
    return outputString.release();
}

int StringCompare(const String &left,
                  const String &right,
                  bool caseInsensitive)
{
    // Convert input strings
    std::unique_ptr<UChar[]> leftICU(ConvertToICU(left));
    std::unique_ptr<UChar[]> rightICU(ConvertToICU(right));

    if (caseInsensitive) {
        return static_cast<int>(u_strcasecmp(leftICU.get(), rightICU.get(), 0));
    } else {
        return static_cast<int>(u_strcmp(leftICU.get(), rightICU.get()));
    }
}
} //namespace CKM

std::ostream& operator<<(std::ostream& aStream, const CKM::String& aString)
{
    return aStream << CKM::ToUTF8String(aString);
}
