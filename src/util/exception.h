#pragma once

#include <cstdint>
#include <exception>
#include <iostream>
#include <string>

namespace poseidon
{

class poseidon_error : public std::runtime_error
{
public:
    poseidon_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : std::runtime_error(what), filename_(filename), line_num_(line_num)
    {
        comb_message_ = filename_ + ":" + std::to_string(line_num_) + " " + what;
    }

    const char *what() const noexcept { return comb_message_.c_str(); }

    const uint32_t GetLineNum() { return line_num_; }

    const std::string &GetFileNum() { return filename_; }

private:
    std::string filename_;
    uint32_t line_num_;
    std::string comb_message_;
};

class metadata_error : public poseidon_error
{
public:
    metadata_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : poseidon_error(filename, line_num, what)
    {
    }
};

class config_error : public poseidon_error
{
public:
    config_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : poseidon_error(filename, line_num, what)
    {
    }
};

class invalid_argument_error : public poseidon_error
{
public:
    invalid_argument_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : poseidon_error(filename, line_num, what)
    {
    }
};

#define POSEIDON_THROW(exc, expr) throw exc(__FILE__, __LINE__, (expr))
}  // namespace poseidon
