#include <platform/decider.h>

#include <sw-backend/store.h>

namespace CKM {
namespace Crypto {

Decider::Decider()
  : m_store(new SW::Store(CryptoBackend::OpenSSL))
{}

GStoreShPtr Decider::getStore(const Token &) {
    // This the place where we should choose backend bases on token information.
    return m_store;
};

} // namespace Crypto
} // namespace CKM

