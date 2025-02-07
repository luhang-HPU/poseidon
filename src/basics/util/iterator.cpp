#include "src/basics/util/iterator.h"
#include "src//ciphertext.h"

namespace poseidon
{
namespace util
{
PolyIter::PolyIter(Ciphertext &ct)
    : self_type(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_size())
{
}

ConstPolyIter::ConstPolyIter(const Ciphertext &ct)
    : self_type(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_size())
{
}

ConstPolyIter::ConstPolyIter(Ciphertext &ct)
    : self_type(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_size())
{
}
}  // namespace util
}  // namespace poseidon
