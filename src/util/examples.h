#pragma once

#include <iostream>
#include <string>
namespace poseidon
{
namespace util
{
inline void print_example_banner(std::string title)
{
    if (!title.empty())
    {
        std::size_t title_length = title.length();
        std::size_t banner_length = title_length + 2 * 10;
        std::string banner_top = "+" + std::string(banner_length - 2, '-') + "+";
        std::string banner_middle = "|" + std::string(9, ' ') + title + std::string(9, ' ') + "|";

        std::cout << std::endl
                  << banner_top << std::endl
                  << banner_middle << std::endl
                  << banner_top << std::endl;
    }
}
}  // namespace util
}  // namespace poseidon
