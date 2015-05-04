#pragma once

#include <memory>

#include <generic-backend/gstore.h>
#include <generic-backend/token.h>

namespace CKM {
namespace Crypto {

class Decider {
public:
    Decider();
    GStoreShPtr getStore(const Token &token);
    virtual ~Decider(){}
private:
    GStoreShPtr m_store;
};

} // Crypto
} // CKM

