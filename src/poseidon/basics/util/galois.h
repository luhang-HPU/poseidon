#pragma once

#include "poseidon/basics/memorymanager.h"
#include "poseidon/basics/modulus.h"
#include "poseidon/basics/util/defines.h"
#include "poseidon/basics/util/iterator.h"
#include "poseidon/basics/util/pointer.h"
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace poseidon
{
namespace util
{
class GaloisTool
{
public:
    GaloisTool(int coeff_count_power, MemoryPoolHandle pool) : pool_(std::move(pool))
    {
        if (!pool_)
        {
            throw std::invalid_argument("pool is uninitialized");
        }

        initialize(coeff_count_power);
    }

    void apply_galois(ConstCoeffIter operand, std::uint32_t galois_elt, const Modulus &modulus,
                      CoeffIter result) const;

    inline void apply_galois(ConstRNSIter operand, std::size_t coeff_modulus_size,
                             std::uint32_t galois_elt, ConstModulusIter modulus,
                             RNSIter result) const
    {
#ifdef POSEIDON_DEBUG
        if ((!operand && coeff_modulus_size > 0) || (operand.poly_modulus_degree() != coeff_count_))
        {
            throw std::invalid_argument("operand");
        }
        if ((!result && coeff_modulus_size > 0) || (result.poly_modulus_degree() != coeff_count_))
        {
            throw std::invalid_argument("result");
        }
#endif
        POSEIDON_ITERATE(iter(operand, modulus, result), coeff_modulus_size,
                         [&](auto I)
                         { this->apply_galois(get<0>(I), galois_elt, get<1>(I), get<2>(I)); });
    }

    void apply_galois(ConstPolyIter operand, std::size_t size, std::uint32_t galois_elt,
                      ConstModulusIter modulus, PolyIter result) const
    {
#ifdef POSEIDON_DEBUG
        if (!operand && size > 0)
        {
            throw std::invalid_argument("operand");
        }
        if (!result && size > 0)
        {
            throw std::invalid_argument("result");
        }
        if (operand.coeff_modulus_size() != result.coeff_modulus_size())
        {
            throw std::invalid_argument("incompatible iterators");
        }
#endif
        auto coeff_modulus_size = result.coeff_modulus_size();
        POSEIDON_ITERATE(
            iter(operand, result), size,
            [&](auto I)
            { this->apply_galois(get<0>(I), coeff_modulus_size, galois_elt, modulus, get<1>(I)); });
    }

    void apply_galois_ntt(ConstCoeffIter operand, std::uint32_t galois_elt, CoeffIter result) const;

    void apply_galois_ntt(ConstRNSIter operand, std::size_t coeff_modulus_size,
                          std::uint32_t galois_elt, RNSIter result) const
    {
#ifdef POSEIDON_DEBUG
        if ((!operand && coeff_modulus_size > 0) || (operand.poly_modulus_degree() != coeff_count_))
        {
            throw std::invalid_argument("operand");
        }
        if ((!result && coeff_modulus_size > 0) || (result.poly_modulus_degree() != coeff_count_))
        {
            throw std::invalid_argument("result");
        }
#endif
        POSEIDON_ITERATE(iter(operand, result), coeff_modulus_size,
                         [&](auto I) { this->apply_galois_ntt(get<0>(I), galois_elt, get<1>(I)); });
    }

    void apply_galois_ntt(ConstPolyIter operand, std::size_t size, std::uint32_t galois_elt,
                          PolyIter result) const
    {
#ifdef POSEIDON_DEBUG
        if (!operand && size > 0)
        {
            throw std::invalid_argument("operand");
        }
        if (!result && size > 0)
        {
            throw std::invalid_argument("result");
        }
        if (operand.coeff_modulus_size() != result.coeff_modulus_size())
        {
            throw std::invalid_argument("incompatible iterators");
        }
#endif
        auto coeff_modulus_size = result.coeff_modulus_size();
        POSEIDON_ITERATE(
            iter(operand, result), size,
            [&](auto I)
            { this->apply_galois_ntt(get<0>(I), coeff_modulus_size, galois_elt, get<1>(I)); });
    }

    /**
    Compute the Galois element corresponding to a given rotation step.
    */
    POSEIDON_NODISCARD std::uint32_t get_elt_from_step(int step) const;

    /**
    Compute the Galois elements corresponding to a vector of given rotation steps.
    */
    POSEIDON_NODISCARD std::vector<std::uint32_t>
    get_elts_from_steps(const std::vector<int> &steps) const;

    /**
    Compute a vector of all necessary galois_elts.
    */
    POSEIDON_NODISCARD std::vector<std::uint32_t> get_elts_all() const noexcept;

    /**
    Compute the index in the range of 0 to (coeff_count_ - 1) of a given Galois element.
    */
    POSEIDON_NODISCARD static inline std::size_t GetIndexFromElt(std::uint32_t galois_elt)
    {
#ifdef POSEIDON_DEBUG
        if (!(galois_elt & 1))
        {
            throw std::invalid_argument("galois_elt is not valid");
        }
#endif
        return util::safe_cast<std::size_t>((galois_elt - 1) >> 1);
    }

    void generate_table_ntt(std::uint32_t galois_elt, Pointer<std::uint32_t> &result) const;

private:
    GaloisTool(const GaloisTool &copy) = delete;

    GaloisTool(GaloisTool &&source) = delete;

    GaloisTool &operator=(const GaloisTool &assign) = delete;

    GaloisTool &operator=(GaloisTool &&assign) = delete;

    void initialize(int coeff_count_power);

    MemoryPoolHandle pool_;

    int coeff_count_power_ = 0;

    std::size_t coeff_count_ = 0;

    static constexpr std::uint32_t generator_ = 5;

    mutable Pointer<Pointer<std::uint32_t>> permutation_tables_;

    mutable util::ReaderWriterLocker permutation_tables_locker_;
};
}  // namespace util
}  // namespace poseidon
