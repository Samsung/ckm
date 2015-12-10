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
/**
 * @file    serialization.h
 * @author  Tomasz Swierczek (t.swierczek@samsung.com)
 * @version 1.0
 * @brief   Interfaces and templates used for data serialization.
 */
#ifndef CENT_KEY_SERIALIZATION_H
#define CENT_KEY_SERIALIZATION_H

#include <stdint.h>

#include <string>
#include <vector>
#include <list>
#include <map>
#include <memory>

namespace CKM {
// Abstract data stream buffer
class IStream {
  public:
    virtual void Read(size_t num, void * bytes) = 0;
    virtual void Write(size_t num, const void * bytes) = 0;
    virtual ~IStream(){}
};

// Serializable interface
class ISerializable {
  public:
    /*    ISerializable(){};
     *    ISerializable(IStream&){}; */
    virtual void Serialize(IStream &) const = 0;
    virtual ~ISerializable(){}
};

struct Serialization {
    // serialization
    // normal functions

    // ISerializable objects
    static void Serialize(IStream& stream, const ISerializable& object)
    {
        object.Serialize(stream);
    }

    static void Serialize(IStream& stream, const ISerializable* const object)
    {
        object->Serialize(stream);
    }

    // char
    static void Serialize(IStream& stream, const char value)
    {
        stream.Write(sizeof(value), &value);
    }
    static void Serialize(IStream& stream, const char* const value)
    {
        stream.Write(sizeof(*value), value);
    }

    // unsigned char
    static void Serialize(IStream& stream, const unsigned char value)
    {
        stream.Write(sizeof(value), &value);
    }
    static void Serialize(IStream& stream, const unsigned char* const value)
    {
        stream.Write(sizeof(*value), value);
    }

    // unsigned int32
    static void Serialize(IStream& stream, const uint32_t value)
    {
        stream.Write(sizeof(value), &value);
    }
    static void Serialize(IStream& stream, const uint32_t* const value)
    {
        stream.Write(sizeof(*value), value);
    }

    // int32
    static void Serialize(IStream& stream, const int32_t value)
    {
        stream.Write(sizeof(value), &value);
    }
    static void Serialize(IStream& stream, const int32_t* const value)
    {
        stream.Write(sizeof(*value), value);
    }

    // unsigned int64
    static void Serialize(IStream& stream, const uint64_t value)
    {
        stream.Write(sizeof(value), &value);
    }
    static void Serialize(IStream& stream, const uint64_t* const value)
    {
        stream.Write(sizeof(*value), value);
    }

    // int64
    static void Serialize(IStream& stream, const int64_t value)
    {
        stream.Write(sizeof(value), &value);
    }
    static void Serialize(IStream& stream, const int64_t* const value)
    {
        stream.Write(sizeof(*value), value);
    }

    // bool
    static void Serialize(IStream& stream, const bool value)
    {
        stream.Write(sizeof(value), &value);
    }
    static void Serialize(IStream& stream, const bool* const value)
    {
        stream.Write(sizeof(*value), value);
    }

    // std::string
    template <typename T, typename R, typename A>
    static void Serialize(IStream& stream, const std::basic_string<T, R, A>& str)
    {
        int length = str.size();
        stream.Write(sizeof(length), &length);
        stream.Write(length*sizeof(T), str.data());
    }

    template<typename T, typename R, typename A>
    static void Serialize(IStream& stream, const std::basic_string<T, R, A>* const str)
    {
        int length = str->size();
        stream.Write(sizeof(length), &length);
        stream.Write(length*sizeof(T), str->data());
    }

    // STL templates

    // std::list
    template <typename T>
    static void Serialize(IStream& stream, const std::list<T>& list)
    {
        int length = list.size();
        stream.Write(sizeof(length), &length);
        for (typename std::list<T>::const_iterator list_iter = list.begin();
             list_iter != list.end(); list_iter++)
            Serialize(stream, *list_iter);
    }
    template <typename T>
    static void Serialize(IStream& stream, const std::list<T>* const list)
    {
        Serialize(stream, *list);
    }

    // RawBuffer
    template <typename A>
    static void Serialize(IStream& stream, const std::vector<unsigned char, A>& vec)
    {
        int length = vec.size();
        stream.Write(sizeof(length), &length);
        stream.Write(length, vec.data());
    }

    template <typename A>
    static void Serialize(IStream& stream, const std::vector<unsigned char, A>* const vec)
    {
        Serialize(stream, *vec);
    }

    // std::vector
    template <typename T, typename A>
    static void Serialize(IStream& stream, const std::vector<T, A>& vec)
    {
        int length = vec.size();
        stream.Write(sizeof(length), &length);
        for (const auto &i : vec)
            Serialize(stream, i);
    }
    template <typename T, typename A>
    static void Serialize(IStream& stream, const std::vector<T, A>* const vec)
    {
        Serialize(stream, *vec);
    }

    // std::pair
    template <typename A, typename B>
    static void Serialize(IStream& stream, const std::pair<A, B>& p)
    {
        Serialize(stream, p.first);
        Serialize(stream, p.second);
    }
    template <typename A, typename B>
    static void Serialize(IStream& stream, const std::pair<A, B>* const p)
    {
        Serialize(stream, *p);
    }

    // std::map
    template <typename K, typename T>
    static void Serialize(IStream& stream, const std::map<K, T>& map)
    {
        int length = map.size();
        stream.Write(sizeof(length), &length);
        typename std::map<K, T>::const_iterator it;
        for (it = map.begin(); it != map.end(); ++it) {
            Serialize(stream, (*it).first);
            Serialize(stream, (*it).second);
        }
    }
    template <typename K, typename T>
    static void Serialize(IStream& stream, const std::map<K, T>* const map)
    {
        Serialize(stream, *map);
    }

    // std::unique_ptr
    template <typename T>
    static void Serialize(IStream& stream, const std::unique_ptr<T>& p)
    {
        Serialize(stream, *p);
    }
}; // struct Serialization

struct Deserialization {
    // deserialization
    // normal functions

    // ISerializable objects
    // T instead of ISerializable is needed to call proper constructor
    template <typename T>
    static void Deserialize(IStream& stream, T& object)
    {
        object = T(stream);
    }
    template <typename T>
    static void Deserialize(IStream& stream, T*& object)
    {
        object = new T(stream);
    }

    // char
    static void Deserialize(IStream& stream, char& value)
    {
        stream.Read(sizeof(value), &value);
    }
    static void Deserialize(IStream& stream, char*& value)
    {
        value = new char;
        stream.Read(sizeof(*value), value);
    }

    // unsigned char
    static void Deserialize(IStream& stream, unsigned char& value)
    {
        stream.Read(sizeof(value), &value);
    }
    static void Deserialize(IStream& stream, unsigned char*& value)
    {
        value = new unsigned char;
        stream.Read(sizeof(*value), value);
    }

    // unsigned int32
    static void Deserialize(IStream& stream, uint32_t& value)
    {
        stream.Read(sizeof(value), &value);
    }
    static void Deserialize(IStream& stream, uint32_t*& value)
    {
        value = new uint32_t;
        stream.Read(sizeof(*value), value);
    }

    // int32
    static void Deserialize(IStream& stream, int32_t& value)
    {
        stream.Read(sizeof(value), &value);
    }
    static void Deserialize(IStream& stream, int32_t*& value)
    {
        value = new int32_t;
        stream.Read(sizeof(*value), value);
    }

    // unsigned int64
    static void Deserialize(IStream& stream, uint64_t& value)
    {
        stream.Read(sizeof(value), &value);
    }
    static void Deserialize(IStream& stream, uint64_t*& value)
    {
        value = new uint64_t;
        stream.Read(sizeof(*value), value);
    }

    // int64
    static void Deserialize(IStream& stream, int64_t& value)
    {
        stream.Read(sizeof(value), &value);
    }
    static void Deserialize(IStream& stream, int64_t*& value)
    {
        value = new int64_t;
        stream.Read(sizeof(*value), value);
    }

    // bool
    static void Deserialize(IStream& stream, bool& value)
    {
        stream.Read(sizeof(value), &value);
    }
    static void Deserialize(IStream& stream, bool*& value)
    {
        value = new bool;
        stream.Read(sizeof(*value), value);
    }

    template <typename T, typename R, typename A>
    static void Deserialize(IStream& stream, std::basic_string<T, R, A>& str)
    {
        int length;
        stream.Read(sizeof(length), &length);
        std::vector<T> buf(length);
        stream.Read(length*sizeof(T), buf.data());
        str = std::basic_string<T, R, A>(buf.data(), buf.data() + length);
    }

    template <typename T, typename R, typename A>
    static void Deserialize(IStream& stream, std::basic_string<T, R, A>*& str)
    {
        int length;
        stream.Read(sizeof(length), &length);
        std::vector<T> buf(length);
        stream.Read(length*sizeof(T), buf.data());
        str = new std::basic_string<T, R, A>(buf.data(), buf.data() + length);
    }

    // STL templates

    // std::list
    template <typename T>
    static void Deserialize(IStream& stream, std::list<T>& list)
    {
        int length;
        stream.Read(sizeof(length), &length);
        for (int i = 0; i < length; ++i) {
            T obj;
            Deserialize(stream, obj);
            list.push_back(std::move(obj));
        }
    }
    template <typename T>
    static void Deserialize(IStream& stream, std::list<T>*& list)
    {
        list = new std::list<T>;
        Deserialize(stream, *list);
    }

    // RawBuffer
    template <typename A>
    static void Deserialize(IStream& stream, std::vector<unsigned char, A>& vec)
    {
        int length;
        stream.Read(sizeof(length), &length);
        vec.resize(length);
        stream.Read(length, vec.data());
    }

    template <typename A>
    static void Deserialize(IStream& stream, std::vector<unsigned char, A>*& vec)
    {
        vec = new std::vector<unsigned char, A>;
        Deserialize(stream, *vec);
    }

    // std::vector
    template <typename T, typename A>
    static void Deserialize(IStream& stream, std::vector<T, A>& vec)
    {
        int length;
        stream.Read(sizeof(length), &length);
        for (int i = 0; i < length; ++i) {
            T obj;
            Deserialize(stream, obj);
            vec.push_back(std::move(obj));
        }
    }
    template <typename T, typename A>
    static void Deserialize(IStream& stream, std::vector<T, A>*& vec)
    {
        vec = new std::vector<T, A>;
        Deserialize(stream, *vec);
    }

    // std::pair
    template <typename A, typename B>
    static void Deserialize(IStream& stream, std::pair<A, B>& p)
    {
        Deserialize(stream, p.first);
        Deserialize(stream, p.second);
    }
    template <typename A, typename B>
    static void Deserialize(IStream& stream, std::pair<A, B>*& p)
    {
        p = new std::pair<A, B>;
        Deserialize(stream, *p);
    }

    // std::map
    template <typename K, typename T>
    static void Deserialize(IStream& stream, std::map<K, T>& map)
    {
        int length;
        stream.Read(sizeof(length), &length);
        for (int i = 0; i < length; ++i) {
            K key;
            T obj;
            Deserialize(stream, key);
            Deserialize(stream, obj);
            map[key] = std::move(obj);
        }
    }
    template <typename K, typename T>
    static void Deserialize(IStream& stream, std::map<K, T>*& map)
    {
        map = new std::map<K, T>;
        Deserialize(stream, *map);
    }
}; // struct Deserialization

// generic serialization
template <typename... Args>
struct Serializer;

template <typename First, typename... Args>
struct Serializer<First, Args...> : public Serializer<Args...> {
    static void Serialize(IStream& stream, const First& f, const Args&... args)
    {
        Serialization::Serialize(stream, f);
        Serializer<Args...>::Serialize(stream, args...);
    }
};

// end of recursion
template <>
struct Serializer<> {
    static void Serialize(IStream&)
    {
        return;
    }
};

// generic deserialization
template <typename... Args>
struct Deserializer;

template <typename First, typename... Args>
struct Deserializer<First, Args...> : public Deserializer<Args...> {
    static void Deserialize(IStream& stream, First& f, Args&... args)
    {
        Deserialization::Deserialize(stream, f);
        Deserializer<Args...>::Deserialize(stream, args...);
    }
};

// end of recursion
template <>
struct Deserializer<> {
    static void Deserialize(IStream&)
    {
        return;
    }
};

} // namespace CKM

#endif // CENT_KEY_SERIALIZATION_H
