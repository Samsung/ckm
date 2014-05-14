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
/*
 * @file        singleton_safe_impl.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of singleton
 */
#ifndef CENT_KEY_SINGLETON_SAFE_IMPL_H
#define CENT_KEY_SINGLETON_SAFE_IMPL_H

#define IMPLEMENT_SAFE_SINGLETON(Class)                                        \
    namespace CentralKeyManager {                                                                \
    template<>                                                                     \
    Singleton<Class>&Singleton<Class>::InternalInstance()                         \
    {                                                                              \
        static Singleton<Class> instance;                                          \
        return instance;                                                           \
    }                                                                              \
                                                                               \
    template<>                                                                     \
    Class & Singleton<Class>::Instance()                                            \
    {                                                                              \
        Singleton<Class>& instance = Singleton<Class>::InternalInstance();         \
        return instance;                                                           \
    }                                                                              \
                                                                               \
    template Singleton<Class>&Singleton<Class>::InternalInstance();               \
    template Class & Singleton<Class>::Instance();                                  \
    } // namespace CentralKeyManager

#endif // CENT_KEY_SINGLETON_SAFE_IMPL_H
