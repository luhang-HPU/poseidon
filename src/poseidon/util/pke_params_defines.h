#pragma once

enum SchemeType : std::uint8_t
{
    default_type = 0x0,
    CKKS = 0x1,
    BFV = 0x2,
    BGV = 0x3
};

enum KeySwitchVariant : std::uint8_t
{
    none = 0x0,
    GHS = 0x1,
    BV = 0x2,
    HYBRID = 0x3
};
