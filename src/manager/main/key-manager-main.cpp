/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        key-manager-main.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of central key manager
 */
#include <stdlib.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <dpl/log/log.h>
#include <dpl/singleton.h>
#include <dpl/singleton_safe_impl.h>

#include <socket-manager.h>

#include <echo.h>
#include <ckm-service.h>

#include <key-provider.h>

IMPLEMENT_SAFE_SINGLETON(CKM::Log::LogSystem);

#define REGISTER_SOCKET_SERVICE(manager, service) \
    registerSocketService<service>(manager, #service)

template<typename T>
void registerSocketService(CKM::SocketManager &manager, const std::string& serviceName)
{
    T *service = NULL;
    try {
        service = new T();
        service->Create();
        manager.RegisterSocketService(service);
        service = NULL;
    } catch (const CKM::Exception &exception) {
        LogError("Error in creating service " << serviceName <<
                 ", details:\n" << exception.DumpToString());
    } catch (const std::exception& e) {
        LogError("Error in creating service " << serviceName <<
                 ", details:\n" << e.what());
    } catch (...) {
        LogError("Error in creating service " << serviceName <<
                 ", unknown exception occured");
    }
    if (service)
        delete service;
}

int main(void) {

    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        CKM::Singleton<CKM::Log::LogSystem>::Instance().SetTag("CENT_KEY_MNG");

        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGPIPE);
        if (-1 == pthread_sigmask(SIG_BLOCK, &mask, NULL)) {
            LogError("Error in pthread_sigmask");
            return 1;
        }
        LogInfo("Init external liblaries SKMM and openssl");

        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_ciphers();
        OPENSSL_config(NULL);

        CKM::KeyProvider::initializeLibrary();

        {
            LogInfo("Start!");
            CKM::SocketManager manager;

            REGISTER_SOCKET_SERVICE(manager, CKM::EchoService);
            REGISTER_SOCKET_SERVICE(manager, CKM::CKMService);

            manager.MainLoop();
        }
        // Manager has been destroyed and we may close external libraries.
        LogInfo("Deinit SKMM and openssl");
        CKM::KeyProvider::closeLibrary();
        // Deinit OPENSSL ?
        EVP_cleanup();
        ERR_free_strings();
    }
    UNHANDLED_EXCEPTION_HANDLER_END
    return 0;
}

