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
 * @file        ckm-manager-main.cpp
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

#include <socket-manager.h>

#include <ckm-service.h>
#include <ocsp-service.h>

#include <key-provider.h>
#include <file-system.h>

/* TODO remove this include */
#include <sw-backend/crypto-service.h>

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
        CKM::Singleton<CKM::Log::LogSystem>::Instance().SetTag("CKM");

        int retCode = CKM::FileSystem::init();
        if (retCode) {
            LogError("Fatal error in FileSystem::init()");
            return 1;
        }

        CKM::FileLock fl = CKM::FileSystem::lock();

        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGPIPE);
        if (-1 == pthread_sigmask(SIG_BLOCK, &mask, NULL)) {
            LogError("Error in pthread_sigmask");
            return 1;
        }
        LogInfo("Init external libraries SKMM and openssl");

        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_ciphers();
        OPENSSL_config(NULL);

        CKM::KeyProvider::initializeLibrary();

        /* ToDO remove it */
        CKM::Crypto::SW::CryptoService::initialize();

        {
            LogInfo("Start!");
            CKM::SocketManager manager;

            REGISTER_SOCKET_SERVICE(manager, CKM::CKMService);
            REGISTER_SOCKET_SERVICE(manager, CKM::OCSPService);

            manager.MainLoop();
        }
        // Manager has been destroyed and we may close external libraries.
        LogInfo("Deinit SKMM and openssl");
        CKM::KeyProvider::closeLibrary();
        // Deinit OPENSSL ?
        EVP_cleanup();
        ERR_free_strings();
    }
    catch (const std::runtime_error& e)
    {
        LogError(e.what());
    }
    UNHANDLED_EXCEPTION_HANDLER_END
    return 0;
}

