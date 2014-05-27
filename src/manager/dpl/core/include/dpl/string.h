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
 * @file        string.h
 * @author      Piotr Marcinkiewicz (p.marcinkiew@samsung.com)
 * @version     1.0
 */
#ifndef CKM_STRING
#define CKM_STRING

#include <dpl/exception.h>
#include <dpl/char_traits.h>
#include <string>
#include <ostream>
#include <numeric>

namespace CKM {
// @brief CKM string
typedef std::basic_string<wchar_t, CharTraits> String;

// @brief String exception class
class StringException
{
  public:
    DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)

    // @brief Invalid init for UTF8 to UTF32 converter
    DECLARE_EXCEPTION_TYPE(Base, IconvInitErrorUTF8ToUTF32)

    // @brief Invalid taStdContainerinit for UTF32 to UTF32 converter
    DECLARE_EXCEPTION_TYPE(Base, IconvInitErrorUTF32ToUTF8)

    // @brief Invalid conversion for UTF8 to UTF32 converter
    DECLARE_EXCEPTION_TYPE(Base, IconvConvertErrorUTF8ToUTF32)

    // @brief Invalid conversion for UTF8 to UTF32 converter
    DECLARE_EXCEPTION_TYPE(Base, IconvConvertErrorUTF32ToUTF8)

    // @brief Invalid ASCII character detected in FromASCII
    DECLARE_EXCEPTION_TYPE(Base, InvalidASCIICharacter)

    // @brief Invalid ASCII character detected in FromASCII
    DECLARE_EXCEPTION_TYPE(Base, ICUInvalidCharacterFound)
};

//!\brief convert ASCII string to CKM::String
String FromASCIIString(const std::string& aString);

//!\brief convert UTF32 string to CKM::String
String FromUTF32String(const std::wstring& aString);

//@brief Returns String object created from UTF8 string
//@param[in] aString input UTF-8 string
String FromUTF8String(const std::string& aString);

//@brief Returns String content as std::string
std::string ToUTF8String(const String& aString);

//@brief Compare two unicode strings
int StringCompare(const String &left,
                  const String &right,
                  bool caseInsensitive = false);

//@brief Splits the string into substrings.
//@param[in] str Input string
//@param[in] delimiters array or string containing a sequence of substring
// delimiters. Can be also a single delimiter character.
//@param[in] it InserterIterator that is used to save the generated substrings.
template<typename StringType, typename Delimiters, typename InserterIterator>
void Tokenize(const StringType& str,
              const Delimiters& delimiters,
              InserterIterator it,
              bool ignoreEmpty = false)
{
    typename StringType::size_type nextSearchStart = 0;
    typename StringType::size_type pos;
    typename StringType::size_type length;

    while (true) {
        pos = str.find_first_of(delimiters, nextSearchStart);
        length =
            ((pos == StringType::npos) ? str.length() : pos) - nextSearchStart;

        if (!ignoreEmpty || length > 0) {
            *it = str.substr(nextSearchStart, length);
            it++;
        }

        if (pos == StringType::npos) {
            return;
        }

        nextSearchStart = pos + 1;
    }
}

namespace Utils {

template<typename T> class ConcatFunc : public std::binary_function<T, T, T>
{
public:
    explicit ConcatFunc(const T & val) : m_delim(val) {}
    T operator()(const T & arg1, const T & arg2) const
    {
        return arg1 + m_delim + arg2;
    }
private:
    T m_delim;
};

}

template<typename ForwardIterator>
typename ForwardIterator::value_type Join(ForwardIterator begin, ForwardIterator end, typename ForwardIterator::value_type delim)
{
    typedef typename ForwardIterator::value_type value;
    if(begin == end) return value();
    Utils::ConcatFunc<value> func(delim);
    ForwardIterator init = begin;
    return std::accumulate(++begin, end, *init, func);
}

template<class StringType> void TrimLeft(StringType & obj, typename StringType::const_pointer separators)
{
    obj.erase(0, obj.find_first_not_of(separators));
}

template<class StringType> void TrimRight(StringType & obj, typename StringType::const_pointer separators)
{
    obj.erase(obj.find_last_not_of(separators)+1);
}

template<class StringType> void Trim(StringType & obj, typename StringType::const_pointer separators)
{
    TrimLeft(obj, separators);
    TrimRight(obj, separators);
}


} //namespace CKM

std::ostream& operator<<(std::ostream& aStream, const CKM::String& aString);

#endif // CKM_STRING
