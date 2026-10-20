#include "address.h"

#include <cstdio>

namespace capa {

std::string Address::repr() const {
    char buf[128];
    switch (type) {
        case AddressType::NO_ADDRESS:
            return "no address";
        case AddressType::ABSOLUTE:
            std::snprintf(buf, sizeof(buf), "absolute(0x%llx)",
                          static_cast<unsigned long long>(value));
            return buf;
        case AddressType::PROCESS:
            if (ppid > 0)
                std::snprintf(buf, sizeof(buf), "process(ppid: %u, pid: %u)", ppid, pid);
            else
                std::snprintf(buf, sizeof(buf), "process(pid: %u)", pid);
            return buf;
        case AddressType::THREAD:
            if (ppid > 0)
                std::snprintf(buf, sizeof(buf),
                              "process(ppid: %u, pid: %u), thread(tid: %u)", ppid, pid, tid);
            else
                std::snprintf(buf, sizeof(buf), "process(pid: %u), thread(tid: %u)", pid, tid);
            return buf;
        case AddressType::FILE_OFFSET:
            std::snprintf(buf, sizeof(buf), "file(0x%llx)",
                          static_cast<unsigned long long>(value));
            return buf;
        case AddressType::RELATIVE_VA:
            std::snprintf(buf, sizeof(buf), "relative(0x%llx)",
                          static_cast<unsigned long long>(value));
            return buf;
        case AddressType::DN_TOKEN:
            std::snprintf(buf, sizeof(buf), "token(0x%llx)",
                          static_cast<unsigned long long>(value));
            return buf;
        case AddressType::DN_TOKEN_OFFSET:
            std::snprintf(buf, sizeof(buf), "token(0x%llx)+(0x%llx)",
                          static_cast<unsigned long long>(value),
                          static_cast<unsigned long long>(id));
            return buf;
        case AddressType::CALL:
            if (ppid > 0)
                std::snprintf(buf, sizeof(buf),
                              "process(ppid: %u, pid: %u), thread(tid: %u), call(id: %llu)",
                              ppid, pid, tid, static_cast<unsigned long long>(id));
            else
                std::snprintf(buf, sizeof(buf),
                              "process(pid: %u), thread(tid: %u), call(id: %llu)",
                              pid, tid, static_cast<unsigned long long>(id));
            return buf;
    }
    return "unknown address";
}

}  // namespace capa
