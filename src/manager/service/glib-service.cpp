/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 *
 * @file        glib-service.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Dbus listener implementation as service.
 */

#include <thread>

#include <dpl/log/log.h>

#include <glib-service.h>
#include <glib-logic.h>

namespace CKM {

GLIBService::GLIBService()
  : m_state(State::NoThread)
  , m_logic(new GLIBLogic())
{}

void GLIBService::Event(const AcceptEvent &) {}
void GLIBService::Event(const WriteEvent &) {}
void GLIBService::Event(const ReadEvent &) {}
void GLIBService::Event(const CloseEvent &) {}
void GLIBService::Event(const SecurityEvent &) {}

void GLIBService::Start(){
    LogDebug("Starting thread!");
    assert(m_state == State::NoThread);
    m_thread = std::thread(ThreadLoopStatic, this);
    m_state = State::Work;
}

void GLIBService::Stop(){
    LogDebug("Stopping thread!");
    assert(m_state == State::Work);
    m_logic->LoopStop();
    m_thread.join();
    m_state = State::NoThread;
    LogDebug("Thread for glib joined!");
}

GLIBService::~GLIBService(){
    delete m_logic;
}

GLIBService::ServiceDescriptionVector GLIBService::GetServiceDescription() {
    return ServiceDescriptionVector();
}

void GLIBService::ThreadLoopStatic(GLIBService *ptr) {
    ptr->ThreadLoop();
}

void GLIBService::ThreadLoop() {
    m_logic->LoopStart();
}

void GLIBService::SetCommManager(CommMgr *manager) {
    m_commMgr = manager;
    m_logic->SetCommManager(manager);
}

} // namespace CKM

