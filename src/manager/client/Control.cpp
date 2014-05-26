#include <message-buffer.h>
#include <client-common.h>

#include <ckm/key-manager.h>

namespace CKM {

class Control::ControlImpl {
public:
    Control(){}
    Control(const Control &) = delete;
    Control(Control &&) = delete;
    Control& operator=(const Control &) = delete;
    Control& operator=(Control &&) = delete;

    static int unlockUserKey(const std::string &user, const RawData &password) const {
        return try_catch([&] {
            if (user.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::UNLOCK_USER_KEY));
            Serialization::Serialize(send, user);
            Serialization::Serialize(send, password);

            int retCode = sendToServer(
                SERVICE_SOCKET_CONTROL,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    static int lockUserKey(const std::string &user) const {
        return try_catch([&] {
            if (user.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::LOCK_USER_KEY));
            Serialization::Serialize(send, user);

            int retCode = sendToServer(
                SERVICE_SOCKET_CONTROL,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    static int removeUserData(const std::string &user) const {
        return try_catch([&] {
            if (user.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::REMOVE_USER_DATA));
            Serialization::Serialize(send, user);

            int retCode = sendToServer(
                SERVICE_SOCKET_CONTROL,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    static int checkUserPassword(const std::string &user, const RawData &oldPassword, const RawData &newPassword) const {
        return try_catch([&] {
            if (user.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::CHANGE_USER_PASSWORD));
            Serialization::Serialize(send, user);
            Serialization::Serialize(send, oldPassword);
            Serialization::Serialize(send, newPassword);

            int retCode = sendToServer(
                SERVICE_SOCKET_CONTROL,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    static int resetUserPassword(const std::string &user, const RawData &newPassword) const {
        return try_catch([&] {
            if (user.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::RESET_USER_PASSWORD));
            Serialization::Serialize(send, user);
            Serialization::Serialize(send, newPassword);

            int retCode = sendToServer(
                SERVICE_SOCKET_CONTROL,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    virtual ~Control(){}
};

int Control::unlockUserKey(const std::string &user, const RawData &password) const {
    return m_impl->unlockUserKey(user, password);
}

int Control::lockUserKey(const std::string &user) const {
    return m_impl->lockUserKey(user);
}

int Control::removeUserData(const std::string &user) const {
    return m_impl->removeUserData(user);
}

int Control::changeUserPassword(const std::string &user, const RawData &oldPassword, const RawData &newPassword) const {
    return m_impl->changeUserPassword(user, oldPassword, newPassword);
}

int Control::resetUserPassword(const std::string &user, const RawData &newPassword) const {
    return m_impl->resetUserPassword(user, newPassword);
}

}

