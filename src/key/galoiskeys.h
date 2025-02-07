#pragma once

#include "kswitchkeys.h"
#include "src/basics/memorymanager.h"
#include "src/basics/util/defines.h"
#include "src/basics/util/galois.h"
#include "src/ciphertext.h"
#include <vector>

namespace poseidon
{
/**
Class to store Galois keys.

@par Slot Rotations
Galois keys are certain types of public keys that are needed to perform encrypted
vector rotation operations on batched ciphertexts. Batched ciphertexts encrypt
a 2-by-(N/2) matrix of modular integers in the BFV scheme, or an N/2-dimensional
vector of complex numbers in the ckks scheme, where N denotes the degree of the
polynomial modulus. In the BFV scheme Galois keys can enable both cyclic rotations
of the encrypted matrix rows, as well as row swaps (column rotations). In the ckks
scheme Galois keys can enable cyclic vector rotations, as well as a complex
conjugation operation.


@par Thread Safety
In general, reading from GaloisKeys is thread-safe as long as no other thread is
concurrently mutating it. This is due to the underlying data structure storing the
Galois keys not being thread-safe.

@see RelinKeys for the class that stores the relinearization keys.
@see KeyGenerator for the class that generates the Galois keys.
*/
class GaloisKeys : public KSwitchKeys
{
public:
    /**
    Returns the index of a Galois key in the backing KSwitchKeys instance that
    corresponds to the given Galois element, assuming that it exists in the
    backing KSwitchKeys.

    @param[in] galois_elt The Galois element
    @throws std::invalid_argument if galois_elt is not valid
    */
    POSEIDON_NODISCARD inline static std::size_t get_index(std::uint32_t galois_elt)
    {
        return util::GaloisTool::GetIndexFromElt(galois_elt);
    }

    /**
    Returns whether a Galois key corresponding to a given Galois element exists.

    @param[in] galois_elt The Galois element
    @throws std::invalid_argument if galois_elt is not valid
    */
    POSEIDON_NODISCARD inline bool has_key(std::uint32_t galois_elt) const
    {
        std::size_t index = get_index(galois_elt);
        return data().size() > index && !data()[index].empty();
    }

    /**
    Returns a const reference to a Galois key. The returned Galois key corresponds
    to the given Galois element.

    @param[in] galois_elt The Galois element
    @throws std::invalid_argument if the key corresponding to galois_elt does not exist
    */
    POSEIDON_NODISCARD inline const auto &key(std::uint32_t galois_elt) const
    {
        return KSwitchKeys::data(get_index(galois_elt));
    }
};
}  // namespace poseidon
