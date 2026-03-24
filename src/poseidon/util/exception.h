#pragma once
#include <cstdint>
#include <exception>
#include <iostream>
#include <string>
#include <stdexcept>

namespace poseidon
{

// Base exception class with file and line information
class poseidon_error : public std::runtime_error
{
public:
    poseidon_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : std::runtime_error(what), filename_(filename), line_num_(line_num)
    {
        comb_message_ = filename_ + ":" + std::to_string(line_num_) + " " + what;
    }

    const char *what() const noexcept override { return comb_message_.c_str(); }

    const uint32_t GetLineNum() const { return line_num_; }

    const std::string &GetFileNum() const { return filename_; }

    virtual ~poseidon_error() = default;

protected:
    std::string filename_;
    uint32_t line_num_;
    std::string comb_message_;
};

// Metadata-related errors
class metadata_error : public poseidon_error
{
public:
    metadata_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : poseidon_error(filename, line_num, what)
    {
    }
};

// Configuration-related errors  
class config_error : public poseidon_error
{
public:
    config_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : poseidon_error(filename, line_num, what)
    {
    }
};

// Invalid argument errors (replaces std::invalid_argument)
class invalid_argument_error : public poseidon_error
{
public:
    invalid_argument_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : poseidon_error(filename, line_num, what)
    {
    }
};

// Logic errors (replaces std::logic_error)
class logic_error : public poseidon_error
{
public:
    logic_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : poseidon_error(filename, line_num, what)
    {
    }
};

// Runtime errors (replaces std::runtime_error)
class runtime_error : public poseidon_error
{
public:
    runtime_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : poseidon_error(filename, line_num, what)
    {
    }
};

// Out of range errors (replaces std::out_of_range)
class out_of_range_error : public poseidon_error
{
public:
    out_of_range_error(const std::string &filename, uint32_t line_num, const std::string &what)
        : poseidon_error(filename, line_num, what)
    {
    }
};

// Backward compatibility macros
#define POSEIDON_THROW(exc, expr) throw exc(__FILE__, __LINE__, (expr))

// New convenience macros for better error messages
#define POSEIDON_THROW_INVALID_ARGUMENT(expr)     throw invalid_argument_error(__FILE__, __LINE__, (expr))

#define POSEIDON_THROW_LOGIC_ERROR(expr)     throw logic_error(__FILE__, __LINE__, (expr))

#define POSEIDON_THROW_RUNTIME_ERROR(expr)     throw runtime_error(__FILE__, __LINE__, (expr))

#define POSEIDON_THROW_OUT_OF_RANGE(expr)     throw out_of_range_error(__FILE__, __LINE__, (expr))

#define POSEIDON_THROW_CONFIG_ERROR(expr)     throw config_error(__FILE__, __LINE__, (expr))

} // namespace poseidon
