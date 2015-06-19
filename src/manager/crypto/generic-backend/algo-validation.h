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
 * @file       algo-validation.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <sstream>
#include <string>
#include <utility>

#include <ckm/ckm-type.h>

#include <exception.h>

namespace CKM {
namespace Crypto {

template<typename T>
T unpack(
    const CryptoAlgorithm &alg,
    ParamName paramName)
{
    T result;
    if (!alg.getParam(paramName, result)) {
        ThrowErr(Exc::Crypto::InputParam, "Wrong input param");
    }
    return result;
}


////////// Validators //////////////

// Always validates as true. Useful for checking parameter existence only
template <typename T>
struct DefaultValidator {
    static bool Check(const T&) { return true; }
    static void Why(std::ostringstream& os) { os << "is ok"; }
};

// Validates as true if parameter value is equal to one of Args
template <typename T>
struct Type {
    template <T ...Args>
    struct Equals;

    template <T First>
    struct Equals<First> {
    public:
        static bool Check(const T& value) {
            return First == value;
        }
        static void Why(std::ostringstream& os) {
            os << "doesn't match " << static_cast<int>(First);
        }
    };

    template <T First, T ...Args>
    struct Equals<First, Args...> : public Equals<First>, public Equals<Args...> {
    public:
        static bool Check(const T& value) {
            return Equals<First>::Check(value) || Equals<Args...>::Check(value);
        }
        static void Why(std::ostringstream& os) {
            Equals<First>::Why(os);
            os << ", ";
            Equals<Args...>::Why(os);
        }
    };
};


////////// Getters //////////////

// simply returns parameter value
template <typename T>
struct DefaultGetter {
    static T Get(const T& value) { return value; }
    static void What(std::ostringstream& os) { os << "value"; }
};

// returns buffer param size
struct BufferSizeGetter {
    static size_t Get(const RawBuffer& buffer) { return buffer.size(); }
    static void What(std::ostringstream& os) { os << "buffer size"; }
};


////////// ErrorHandlers //////////////

struct ThrowingHandler {
    static void Handle(std::string message) {
        ThrowErr(Exc::Crypto::InputParam, message);
    }
};


// base class for parameter check
struct ParamCheckBase {
    virtual ~ParamCheckBase() {}
    virtual void Check(const CryptoAlgorithm& ca) const = 0;
};

typedef std::unique_ptr<const ParamCheckBase> ParamCheckBasePtr;

typedef std::vector<ParamCheckBasePtr> ValidatorVector;


// ValidatorVector builder. Creates a vector of ParamCheckBasePtr's specified as Args
template <typename ...Args>
struct VBuilder;

template <typename First>
struct VBuilder<First> {
static ValidatorVector Build() {
        ValidatorVector validators;
        Add(validators);
        return validators;
    }
protected:
    static void Add(ValidatorVector& validators) {
        validators.emplace_back(new First);
    }
};

template <typename First, typename ...Args>
struct VBuilder<First, Args...> : public VBuilder<First>, public VBuilder<Args...> {
    static ValidatorVector Build() {
        ValidatorVector validators;
        Add(validators);
        return validators;
    }
protected:
    static void Add(ValidatorVector& validators) {
        VBuilder<First>::Add(validators);
        VBuilder<Args...>::Add(validators);
    }
};

/*
 * Generic struct responsible for checking a single constraint on given algorithm parameter
 *
 * Name - name of param to check
 * Type - type of param value
 * Mandatory - true if param is mandatory
 * Validator - class providing validation function bool Check(const CryptoAlgorithm&)
 * Getter - gets the value used for validation (param value itself or a buffer size for example)
 * ErrorHandler - class providing method for error handling void Handle(std::string)
 */

template <ParamName Name,
          typename Type,
          bool Mandatory,
          typename Validator = DefaultValidator<Type>,
          typename Getter = DefaultGetter<Type>,
          typename ErrorHandler = ThrowingHandler>
struct ParamCheck : public ParamCheckBase {
    void Check(const CryptoAlgorithm& ca) const {
        Type value;
        std::ostringstream os;

        // check existence
        if(!ca.getParam(Name,value)) {
            if (Mandatory) {
                os << "Mandatory parameter " << static_cast<int>(Name) << " doesn't exist";
                ErrorHandler::Handle(os.str());
            }
            return;
        }
        // validate
        if(!Validator::Check(Getter::Get(value))) {
            os << "The ";
            Getter::What(os);
            os << " of param '" << static_cast<int>(Name) << "'=" <<
                  static_cast<int>(Getter::Get(value)) << " ";
            Validator::Why(os);
            ErrorHandler::Handle(os.str());
        }
    }
};

} // namespace Crypto
} // namespace CKM
