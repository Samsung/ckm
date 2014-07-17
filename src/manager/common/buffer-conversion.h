#pragma once

#include <string.h>

#include <ckm/ckm-type.h>
#include <safe-buffer.h>

namespace CKM {

inline RawBuffer toRawBuffer(const SafeBuffer &safe) {
    RawBuffer output(safe.size());
    memcpy(output.data(), safe.data(), safe.size());
    return output;
}

inline SafeBuffer toSafeBuffer(const RawBuffer &raw) {
    SafeBuffer output(raw.size());
    memcpy(output.data(), raw.data(), raw.size());
    return output;
}

} // namespace CKM

