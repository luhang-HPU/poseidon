#pragma once

#include "poseidon/basics/util/common.h"
#include "poseidon/basics/util/defines.h"
#include "poseidon/basics/util/mempool.h"
#include <iterator>
#include <memory>
#include <type_traits>
#include <utility>

namespace poseidon
{
namespace util
{
// Specialization for poseidon_byte
template <> class POSEIDON_NODISCARD Pointer<poseidon_byte>
{
    friend class MemoryPoolST;
    friend class MemoryPoolMT;

public:
    template <typename, typename> friend class Pointer;
    template <typename, typename> friend class ConstPointer;

    Pointer() = default;

    // Move of the same type
    Pointer(Pointer<poseidon_byte> &&source) noexcept
        : data_(source.data_), head_(source.head_), item_(source.item_), alias_(source.alias_)
    {
        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Move of the same type
    Pointer(Pointer<poseidon_byte> &&source, poseidon_byte value) : Pointer(std::move(source))
    {
        std::fill_n(data_, head_->item_byte_count(), value);
    }

    // Copy a range of elements
    template <typename InputIt>
    Pointer(InputIt first, Pointer<poseidon_byte> &&source) : Pointer(std::move(source))
    {
        std::copy_n(first, head_->item_byte_count(), data_);
    }

    POSEIDON_NODISCARD inline poseidon_byte &operator[](std::size_t index) { return data_[index]; }

    POSEIDON_NODISCARD inline const poseidon_byte &operator[](std::size_t index) const
    {
        return data_[index];
    }

    inline auto &operator=(Pointer<poseidon_byte> &&assign) noexcept
    {
        acquire(std::move(assign));
        return *this;
    }

    POSEIDON_NODISCARD inline bool is_set() const noexcept { return data_ != nullptr; }

    POSEIDON_NODISCARD inline poseidon_byte *get() const noexcept { return data_; }

    POSEIDON_NODISCARD inline poseidon_byte *operator->() const noexcept { return data_; }

    POSEIDON_NODISCARD inline poseidon_byte &operator*() const { return *data_; }

    POSEIDON_NODISCARD inline bool is_alias() const noexcept { return alias_; }

    inline void release() noexcept
    {
        if (head_)
        {
            // Return the memory to pool
            head_->add(item_);
        }
        else if (data_ && !alias_)
        {
            // Free the memory
            delete[] data_;
        }

        data_ = nullptr;
        head_ = nullptr;
        item_ = nullptr;
        alias_ = false;
    }

    void acquire(Pointer<poseidon_byte> &other) noexcept
    {
        if (this == &other)
        {
            return;
        }

        release();

        data_ = other.data_;
        head_ = other.head_;
        item_ = other.item_;
        alias_ = other.alias_;
        other.data_ = nullptr;
        other.head_ = nullptr;
        other.item_ = nullptr;
        other.alias_ = false;
    }

    inline void acquire(Pointer<poseidon_byte> &&other) noexcept { acquire(other); }

    ~Pointer() noexcept { release(); }

    POSEIDON_NODISCARD explicit operator bool() const noexcept { return (data_ != nullptr); }

    POSEIDON_NODISCARD inline static Pointer<poseidon_byte> Owning(poseidon_byte *pointer) noexcept
    {
        return {pointer, false};
    }

    POSEIDON_NODISCARD inline static auto Aliasing(poseidon_byte *pointer) noexcept
        -> Pointer<poseidon_byte>
    {
        return {pointer, true};
    }

private:
    Pointer(const Pointer<poseidon_byte> &copy) = delete;

    Pointer<poseidon_byte> &operator=(const Pointer<poseidon_byte> &assign) = delete;

    Pointer(poseidon_byte *pointer, bool alias) noexcept : data_(pointer), alias_(alias) {}

    Pointer(class MemoryPoolHead *head)
    {
#ifdef POSEIDON_DEBUG
        if (!head)
        {
            throw std::invalid_argument("head cannot be null");
        }
#endif
        head_ = head;
        item_ = head->get();
        data_ = item_->data();
    }

    poseidon_byte *data_ = nullptr;

    MemoryPoolHead *head_ = nullptr;

    MemoryPoolItem *item_ = nullptr;

    bool alias_ = false;
};

template <typename T, typename> class POSEIDON_NODISCARD Pointer
{
    friend class MemoryPoolST;
    friend class MemoryPoolMT;

public:
    friend class Pointer<poseidon_byte>;
    friend class ConstPointer<poseidon_byte>;
    friend class ConstPointer<T>;

    Pointer() = default;

    // Move of the same type
    Pointer(Pointer<T> &&source) noexcept
        : data_(source.data_), head_(source.head_), item_(source.item_), alias_(source.alias_)
    {
        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Move when T is not poseidon_byte
    Pointer(Pointer<poseidon_byte> &&source)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!source.head_ && source.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        head_ = source.head_;
        item_ = source.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            POSEIDON_IF_CONSTEXPR(!std::is_trivially_constructible<T>::value)
            {
                auto count = head_->item_byte_count() / sizeof(T);
                for (auto alloc_ptr = data_; count--; alloc_ptr++)
                {
                    new (alloc_ptr) T;
                }
            }
        }
        alias_ = source.alias_;

        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Move when T is not poseidon_byte
    template <typename... Args> Pointer(Pointer<poseidon_byte> &&source, Args &&...args)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!source.head_ && source.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        head_ = source.head_;
        item_ = source.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            auto count = head_->item_byte_count() / sizeof(T);
            for (auto alloc_ptr = data_; count--; alloc_ptr++)
            {
                new (alloc_ptr) T(std::forward<Args>(args)...);
            }
        }
        alias_ = source.alias_;

        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Copy a range when T is not poseidon_byte
    template <typename InputIt> Pointer(InputIt first, Pointer<poseidon_byte> &&source)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!source.head_ && source.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        head_ = source.head_;
        item_ = source.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            auto count = head_->item_byte_count() / sizeof(T);
            std::uninitialized_copy_n(first, count, data_);
        }
        alias_ = source.alias_;

        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    POSEIDON_NODISCARD inline T &operator[](std::size_t index) { return data_[index]; }

    POSEIDON_NODISCARD inline const T &operator[](std::size_t index) const { return data_[index]; }

    inline auto &operator=(Pointer<T> &&assign) noexcept
    {
        acquire(std::move(assign));
        return *this;
    }

    inline auto &operator=(Pointer<poseidon_byte> &&assign)
    {
        acquire(std::move(assign));
        return *this;
    }

    POSEIDON_NODISCARD inline bool is_set() const noexcept { return data_ != nullptr; }

    POSEIDON_NODISCARD inline T *get() const noexcept { return data_; }

    POSEIDON_NODISCARD inline T *operator->() const noexcept { return data_; }

    POSEIDON_NODISCARD inline T &operator*() const { return *data_; }

    POSEIDON_NODISCARD inline bool is_alias() const noexcept { return alias_; }

    inline void release() noexcept
    {
        if (head_)
        {
            POSEIDON_IF_CONSTEXPR(!std::is_trivially_destructible<T>::value)
            {
                // Manual destructor calls
                auto count = head_->item_byte_count() / sizeof(T);
                for (auto alloc_ptr = data_; count--; alloc_ptr++)
                {
                    alloc_ptr->~T();
                }
            }

            // Return the memory to pool
            head_->add(item_);
        }
        else if (data_ && !alias_)
        {
            // Free the memory
            delete[] data_;
        }

        data_ = nullptr;
        head_ = nullptr;
        item_ = nullptr;
        alias_ = false;
    }

    void acquire(Pointer<T> &other) noexcept
    {
        if (this == &other)
        {
            return;
        }

        release();

        data_ = other.data_;
        head_ = other.head_;
        item_ = other.item_;
        alias_ = other.alias_;
        other.data_ = nullptr;
        other.head_ = nullptr;
        other.item_ = nullptr;
        other.alias_ = false;
    }

    inline void acquire(Pointer<T> &&other) noexcept { acquire(other); }

    void acquire(Pointer<poseidon_byte> &other)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!other.head_ && other.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        release();

        head_ = other.head_;
        item_ = other.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            POSEIDON_IF_CONSTEXPR(!std::is_trivially_constructible<T>::value)
            {
                auto count = head_->item_byte_count() / sizeof(T);
                for (auto alloc_ptr = data_; count--; alloc_ptr++)
                {
                    new (alloc_ptr) T;
                }
            }
        }
        alias_ = other.alias_;
        other.data_ = nullptr;
        other.head_ = nullptr;
        other.item_ = nullptr;
        other.alias_ = false;
    }

    inline void acquire(Pointer<poseidon_byte> &&other) { acquire(other); }

    ~Pointer() noexcept { release(); }

    POSEIDON_NODISCARD explicit operator bool() const noexcept { return (data_ != nullptr); }

    POSEIDON_NODISCARD inline static Pointer<T> Owning(T *pointer) noexcept
    {
        return {pointer, false};
    }

    POSEIDON_NODISCARD inline static auto Aliasing(T *pointer) noexcept -> Pointer<T>
    {
        return {pointer, true};
    }

private:
    Pointer(const Pointer<T> &copy) = delete;

    Pointer<T> &operator=(const Pointer<T> &assign) = delete;

    Pointer(T *pointer, bool alias) noexcept : data_(pointer), alias_(alias) {}

    Pointer(class MemoryPoolHead *head)
    {
#ifdef POSEIDON_DEBUG
        if (!head)
        {
            throw std::invalid_argument("head cannot be null");
        }
#endif
        head_ = head;
        item_ = head->get();
        data_ = reinterpret_cast<T *>(item_->data());
        POSEIDON_IF_CONSTEXPR(!std::is_trivially_constructible<T>::value)
        {
            auto count = head_->item_byte_count() / sizeof(T);
            for (auto alloc_ptr = data_; count--; alloc_ptr++)
            {
                new (alloc_ptr) T;
            }
        }
    }

    template <typename... Args> Pointer(class MemoryPoolHead *head, Args &&...args)
    {
#ifdef POSEIDON_DEBUG
        if (!head)
        {
            throw std::invalid_argument("head cannot be null");
        }
#endif
        head_ = head;
        item_ = head->get();
        data_ = reinterpret_cast<T *>(item_->data());
        auto count = head_->item_byte_count() / sizeof(T);
        for (auto alloc_ptr = data_; count--; alloc_ptr++)
        {
            new (alloc_ptr) T(std::forward<Args>(args)...);
        }
    }

    template <typename InputIt> Pointer(InputIt first, class MemoryPoolHead *head)
    {
#ifdef POSEIDON_DEBUG
        if (!head)
        {
            throw std::invalid_argument("head cannot be null");
        }
#endif
        head_ = head;
        item_ = head->get();
        data_ = reinterpret_cast<T *>(item_->data());
        auto count = head_->item_byte_count() / sizeof(T);
        std::uninitialized_copy_n(first, count, data_);
    }

    T *data_ = nullptr;

    MemoryPoolHead *head_ = nullptr;

    MemoryPoolItem *item_ = nullptr;

    bool alias_ = false;
};

// Specialization for poseidon_byte
template <> class POSEIDON_NODISCARD ConstPointer<poseidon_byte>
{
    friend class MemoryPoolST;
    friend class MemoryPoolMT;

public:
    template <typename, typename> friend class ConstPointer;

    ConstPointer() = default;

    // Move of the same type
    ConstPointer(Pointer<poseidon_byte> &&source) noexcept
        : data_(source.data_), head_(source.head_), item_(source.item_), alias_(source.alias_)
    {
        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Move of the same type
    ConstPointer(Pointer<poseidon_byte> &&source, poseidon_byte value)
        : ConstPointer(std::move(source))
    {
        std::fill_n(data_, head_->item_byte_count(), value);
    }

    // Move of the same type
    ConstPointer(ConstPointer<poseidon_byte> &&source) noexcept
        : data_(source.data_), head_(source.head_), item_(source.item_), alias_(source.alias_)
    {
        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Move of the same type
    ConstPointer(ConstPointer<poseidon_byte> &&source, poseidon_byte value)
        : ConstPointer(std::move(source))
    {
        std::fill_n(data_, head_->item_byte_count(), value);
    }

    // Copy a range of elements
    template <typename InputIt>
    ConstPointer(InputIt first, ConstPointer<poseidon_byte> &&source)
        : ConstPointer(std::move(source))
    {
        std::copy_n(first, head_->item_byte_count(), data_);
    }

    inline auto &operator=(ConstPointer<poseidon_byte> &&assign) noexcept
    {
        acquire(std::move(assign));
        return *this;
    }

    inline auto &operator=(Pointer<poseidon_byte> &&assign) noexcept
    {
        acquire(std::move(assign));
        return *this;
    }

    POSEIDON_NODISCARD inline const poseidon_byte &operator[](std::size_t index) const
    {
        return data_[index];
    }

    POSEIDON_NODISCARD inline bool is_set() const noexcept { return data_ != nullptr; }

    POSEIDON_NODISCARD inline const poseidon_byte *get() const noexcept { return data_; }

    POSEIDON_NODISCARD inline const poseidon_byte *operator->() const noexcept { return data_; }

    POSEIDON_NODISCARD inline const poseidon_byte &operator*() const { return *data_; }

    inline void release() noexcept
    {
        if (head_)
        {
            // Return the memory to pool
            head_->add(item_);
        }
        else if (data_ && !alias_)
        {
            // Free the memory
            delete[] data_;
        }

        data_ = nullptr;
        head_ = nullptr;
        item_ = nullptr;
        alias_ = false;
    }

    void acquire(Pointer<poseidon_byte> &other) noexcept
    {
        release();

        data_ = other.data_;
        head_ = other.head_;
        item_ = other.item_;
        alias_ = other.alias_;
        other.data_ = nullptr;
        other.head_ = nullptr;
        other.item_ = nullptr;
        other.alias_ = false;
    }

    inline void acquire(Pointer<poseidon_byte> &&other) noexcept { acquire(other); }

    void acquire(ConstPointer<poseidon_byte> &other) noexcept
    {
        if (this == &other)
        {
            return;
        }

        release();

        data_ = other.data_;
        head_ = other.head_;
        item_ = other.item_;
        alias_ = other.alias_;
        other.data_ = nullptr;
        other.head_ = nullptr;
        other.item_ = nullptr;
        other.alias_ = false;
    }

    inline void acquire(ConstPointer<poseidon_byte> &&other) noexcept { acquire(other); }

    ~ConstPointer() noexcept { release(); }

    POSEIDON_NODISCARD explicit operator bool() const { return (data_ != nullptr); }

    POSEIDON_NODISCARD inline static auto Owning(poseidon_byte *pointer) noexcept
        -> ConstPointer<poseidon_byte>
    {
        return {pointer, false};
    }

    POSEIDON_NODISCARD inline static auto Aliasing(const poseidon_byte *pointer) noexcept
        -> ConstPointer<poseidon_byte>
    {
        return {const_cast<poseidon_byte *>(pointer), true};
    }

private:
    ConstPointer(const ConstPointer<poseidon_byte> &copy) = delete;

    ConstPointer &operator=(const ConstPointer<poseidon_byte> &assign) = delete;

    ConstPointer(poseidon_byte *pointer, bool alias) noexcept : data_(pointer), alias_(alias) {}

    ConstPointer(class MemoryPoolHead *head)
    {
#ifdef POSEIDON_DEBUG
        if (!head)
        {
            throw std::invalid_argument("head cannot be null");
        }
#endif
        head_ = head;
        item_ = head->get();
        data_ = item_->data();
    }

    poseidon_byte *data_ = nullptr;

    MemoryPoolHead *head_ = nullptr;

    MemoryPoolItem *item_ = nullptr;

    bool alias_ = false;
};

template <typename T, typename> class POSEIDON_NODISCARD ConstPointer
{
    friend class MemoryPoolST;
    friend class MemoryPoolMT;

public:
    ConstPointer() = default;

    // Move of the same type
    ConstPointer(Pointer<T> &&source) noexcept
        : data_(source.data_), head_(source.head_), item_(source.item_), alias_(source.alias_)
    {
        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Move when T is not poseidon_byte
    ConstPointer(Pointer<poseidon_byte> &&source)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!source.head_ && source.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        head_ = source.head_;
        item_ = source.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            POSEIDON_IF_CONSTEXPR(!std::is_trivially_constructible<T>::value)
            {
                auto count = head_->item_byte_count() / sizeof(T);
                for (auto alloc_ptr = data_; count--; alloc_ptr++)
                {
                    new (alloc_ptr) T;
                }
            }
        }
        alias_ = source.alias_;

        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Move when T is not poseidon_byte
    template <typename... Args> ConstPointer(Pointer<poseidon_byte> &&source, Args &&...args)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!source.head_ && source.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        head_ = source.head_;
        item_ = source.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            auto count = head_->item_byte_count() / sizeof(T);
            for (auto alloc_ptr = data_; count--; alloc_ptr++)
            {
                new (alloc_ptr) T(std::forward<Args>(args)...);
            }
        }
        alias_ = source.alias_;

        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Copy a range when T is not poseidon_byte
    template <typename InputIt> ConstPointer(InputIt first, Pointer<poseidon_byte> &&source)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!source.head_ && source.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        head_ = source.head_;
        item_ = source.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            auto count = head_->item_byte_count() / sizeof(T);
            std::uninitialized_copy_n(first, count, data_);
        }
        alias_ = source.alias_;

        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Move of the same type
    ConstPointer(ConstPointer<T> &&source) noexcept
        : data_(source.data_), head_(source.head_), item_(source.item_), alias_(source.alias_)
    {
        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Move when T is not poseidon_byte
    ConstPointer(ConstPointer<poseidon_byte> &&source)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!source.head_ && source.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        head_ = source.head_;
        item_ = source.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            POSEIDON_IF_CONSTEXPR(!std::is_trivially_constructible<T>::value)
            {
                auto count = head_->item_byte_count() / sizeof(T);
                for (auto alloc_ptr = data_; count--; alloc_ptr++)
                {
                    new (alloc_ptr) T;
                }
            }
        }
        alias_ = source.alias_;

        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Move when T is not poseidon_byte
    template <typename... Args> ConstPointer(ConstPointer<poseidon_byte> &&source, Args &&...args)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!source.head_ && source.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        head_ = source.head_;
        item_ = source.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            auto count = head_->item_byte_count() / sizeof(T);
            for (auto alloc_ptr = data_; count--; alloc_ptr++)
            {
                new (alloc_ptr) T(std::forward<Args>(args)...);
            }
        }
        alias_ = source.alias_;

        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    // Copy a range when T is not poseidon_byte
    template <typename InputIt> ConstPointer(InputIt first, ConstPointer<poseidon_byte> &&source)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!source.head_ && source.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        head_ = source.head_;
        item_ = source.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            auto count = head_->item_byte_count() / sizeof(T);
            std::uninitialized_copy_n(first, count, data_);
        }
        alias_ = source.alias_;

        source.data_ = nullptr;
        source.head_ = nullptr;
        source.item_ = nullptr;
        source.alias_ = false;
    }

    inline auto &operator=(ConstPointer<T> &&assign) noexcept
    {
        acquire(std::move(assign));
        return *this;
    }

    inline auto &operator=(ConstPointer<poseidon_byte> &&assign)
    {
        acquire(std::move(assign));
        return *this;
    }

    inline auto &operator=(Pointer<T> &&assign) noexcept
    {
        acquire(std::move(assign));
        return *this;
    }

    inline auto &operator=(Pointer<poseidon_byte> &&assign)
    {
        acquire(std::move(assign));
        return *this;
    }

    POSEIDON_NODISCARD inline const T &operator[](std::size_t index) const { return data_[index]; }

    POSEIDON_NODISCARD inline bool is_set() const noexcept { return data_ != nullptr; }

    POSEIDON_NODISCARD inline const T *get() const noexcept { return data_; }

    POSEIDON_NODISCARD inline const T *operator->() const noexcept { return data_; }

    POSEIDON_NODISCARD inline const T &operator*() const { return *data_; }

    inline void release() noexcept
    {
        if (head_)
        {
            POSEIDON_IF_CONSTEXPR(!std::is_trivially_destructible<T>::value)
            {
                // Manual destructor calls
                auto count = head_->item_byte_count() / sizeof(T);
                for (auto alloc_ptr = data_; count--; alloc_ptr++)
                {
                    alloc_ptr->~T();
                }
            }

            // Return the memory to pool
            head_->add(item_);
        }
        else if (data_ && !alias_)
        {
            // Free the memory
            delete[] data_;
        }

        data_ = nullptr;
        head_ = nullptr;
        item_ = nullptr;
        alias_ = false;
    }

    void acquire(ConstPointer<T> &other) noexcept
    {
        if (this == &other)
        {
            return;
        }

        release();

        data_ = other.data_;
        head_ = other.head_;
        item_ = other.item_;
        alias_ = other.alias_;
        other.data_ = nullptr;
        other.head_ = nullptr;
        other.item_ = nullptr;
        other.alias_ = false;
    }

    inline void acquire(ConstPointer<T> &&other) noexcept { acquire(other); }

    void acquire(ConstPointer<poseidon_byte> &other)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!other.head_ && other.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        release();

        head_ = other.head_;
        item_ = other.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            POSEIDON_IF_CONSTEXPR(!std::is_trivially_constructible<T>::value)
            {
                auto count = head_->item_byte_count() / sizeof(T);
                for (auto alloc_ptr = data_; count--; alloc_ptr++)
                {
                    new (alloc_ptr) T;
                }
            }
        }
        alias_ = other.alias_;
        other.data_ = nullptr;
        other.head_ = nullptr;
        other.item_ = nullptr;
        other.alias_ = false;
    }

    inline void acquire(ConstPointer<poseidon_byte> &&other) { acquire(other); }

    void acquire(Pointer<T> &other) noexcept
    {
        release();

        data_ = other.data_;
        head_ = other.head_;
        item_ = other.item_;
        alias_ = other.alias_;
        other.data_ = nullptr;
        other.head_ = nullptr;
        other.item_ = nullptr;
        other.alias_ = false;
    }

    inline void acquire(Pointer<T> &&other) noexcept { acquire(other); }

    void acquire(Pointer<poseidon_byte> &other)
    {
        // Cannot acquire a non-pool pointer of different type
        if (!other.head_ && other.data_)
        {
            throw std::invalid_argument("cannot acquire a non-pool pointer of different type");
        }

        release();

        head_ = other.head_;
        item_ = other.item_;
        if (head_)
        {
            data_ = reinterpret_cast<T *>(item_->data());
            POSEIDON_IF_CONSTEXPR(!std::is_trivially_constructible<T>::value)
            {
                auto count = head_->item_byte_count() / sizeof(T);
                for (auto alloc_ptr = data_; count--; alloc_ptr++)
                {
                    new (alloc_ptr) T;
                }
            }
        }
        alias_ = other.alias_;
        other.data_ = nullptr;
        other.head_ = nullptr;
        other.item_ = nullptr;
        other.alias_ = false;
    }

    inline void acquire(Pointer<poseidon_byte> &&other) { acquire(other); }

    ~ConstPointer() noexcept { release(); }

    POSEIDON_NODISCARD explicit operator bool() const noexcept { return (data_ != nullptr); }

    POSEIDON_NODISCARD inline static ConstPointer<T> Owning(T *pointer) noexcept
    {
        return {pointer, false};
    }

    POSEIDON_NODISCARD inline static auto Aliasing(const T *pointer) noexcept -> ConstPointer<T>
    {
        return {const_cast<T *>(pointer), true};
    }

private:
    ConstPointer(const ConstPointer<T> &copy) = delete;

    ConstPointer &operator=(const ConstPointer<T> &assign) = delete;

    ConstPointer(T *pointer, bool alias) noexcept : data_(pointer), alias_(alias) {}

    ConstPointer(class MemoryPoolHead *head)
    {
#ifdef POSEIDON_DEBUG
        if (!head)
        {
            throw std::invalid_argument("head cannot be null");
        }
#endif
        head_ = head;
        item_ = head->get();
        data_ = reinterpret_cast<T *>(item_->data());
        POSEIDON_IF_CONSTEXPR(!std::is_trivially_constructible<T>::value)
        {
            auto count = head_->item_byte_count() / sizeof(T);
            for (auto alloc_ptr = data_; count--; alloc_ptr++)
            {
                new (alloc_ptr) T;
            }
        }
    }

    template <typename... Args> ConstPointer(class MemoryPoolHead *head, Args &&...args)
    {
#ifdef POSEIDON_DEBUG
        if (!head)
        {
            throw std::invalid_argument("head cannot be null");
        }
#endif
        head_ = head;
        item_ = head->get();
        data_ = reinterpret_cast<T *>(item_->data());
        auto count = head_->item_byte_count() / sizeof(T);
        for (auto alloc_ptr = data_; count--; alloc_ptr++)
        {
            new (alloc_ptr) T(std::forward<Args>(args)...);
        }
    }

    template <typename InputIt> ConstPointer(InputIt first, class MemoryPoolHead *head)
    {
#ifdef POSEIDON_DEBUG
        if (!head)
        {
            throw std::invalid_argument("head cannot be null");
        }
#endif
        head_ = head;
        item_ = head->get();
        data_ = reinterpret_cast<T *>(item_->data());
        auto count = head_->item_byte_count() / sizeof(T);
        std::uninitialized_copy_n(first, count, data_);
    }

    T *data_ = nullptr;

    MemoryPoolHead *head_ = nullptr;

    MemoryPoolItem *item_ = nullptr;

    bool alias_ = false;
};

// Allocate single element
template <typename T_, typename... Args,
          typename = std::enable_if_t<std::is_standard_layout<
              typename std::remove_cv<typename std::remove_reference<T_>::type>::type>::value>>
POSEIDON_NODISCARD inline auto allocate(MemoryPool &pool, Args &&...args)
{
    using T = typename std::remove_cv<typename std::remove_reference<T_>::type>::type;
    return Pointer<T>(pool.get_for_byte_count(sizeof(T)), std::forward<Args>(args)...);
}

// Allocate array of elements
template <typename T_, typename... Args,
          typename = std::enable_if_t<std::is_standard_layout<
              typename std::remove_cv<typename std::remove_reference<T_>::type>::type>::value>>
POSEIDON_NODISCARD inline auto allocate(std::size_t count, MemoryPool &pool, Args &&...args)
{
    using T = typename std::remove_cv<typename std::remove_reference<T_>::type>::type;
    return Pointer<T>(pool.get_for_byte_count(mul_safe(count, sizeof(T))),
                      std::forward<Args>(args)...);
}

// Allocate and copy a range of elements
template <typename InputIt,
          typename T_ = typename std::iterator_traits<
              typename std::remove_reference<InputIt>::type>::value_type,
          typename = std::enable_if_t<std::is_standard_layout<
              typename std::remove_cv<typename std::remove_reference<T_>::type>::type>::value>>
POSEIDON_NODISCARD inline auto allocate(InputIt &&first, std::size_t count, MemoryPool &pool)
{
    using T = typename std::remove_cv<typename std::remove_reference<T_>::type>::type;
    return Pointer<T>(std::forward<InputIt>(first),
                      pool.get_for_byte_count(mul_safe(count, sizeof(T))));
}
}  // namespace util
}  // namespace poseidon
