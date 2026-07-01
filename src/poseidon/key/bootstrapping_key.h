#pragma once

#include "poseidon/ciphertext.h"
#include "poseidon/key/keyswitch.h"
#include "poseidon/poseidon_context.h"

namespace poseidon
{

class BootstrappingKey
{
    friend class KeyGenerator;

public:
    BootstrappingKey() = default;

    POSEIDON_NODISCARD inline const Ciphertext &recrypt_ekey() const noexcept
    {
        return recrypt_ekey_;
    }

    POSEIDON_NODISCARD inline Ciphertext &recrypt_ekey() noexcept
    {
        return recrypt_ekey_;
    }

    POSEIDON_NODISCARD inline const KSwitchKeys &switch_key() const noexcept
    {
        return switch_key_;
    }

    POSEIDON_NODISCARD inline KSwitchKeys &switch_key() noexcept
    {
        return switch_key_;
    }

    POSEIDON_NODISCARD inline const parms_id_type &parms_id() const noexcept
    {
        return recrypt_ekey_.parms_id();
    }

    POSEIDON_NODISCARD inline MemoryPoolHandle pool() const noexcept
    {
        return recrypt_ekey_.pool();
    }

    POSEIDON_NODISCARD inline bool is_valid() const noexcept
    {
        return recrypt_ekey_.is_valid();
    }

private:
    Ciphertext recrypt_ekey_;
    KSwitchKeys switch_key_;
};

} // namespace poseidon
