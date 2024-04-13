#pragma once

#include <memory>
#include <Windows.h>









template <typename T>
struct HandleDeleter 
{
    void operator()(T handle) const 
    {
        if (handle != INVALID_HANDLE_VALUE) 
        {
            CloseHandle(handle);
        }
    }
};


template <typename T>
class UniqueHandle 
{

    std::unique_ptr<std::remove_pointer_t<T>, HandleDeleter<T>> m_handle;

    bool CheckAlignment(size_t alignment) const;
    

public:

    UniqueHandle(T handle) : m_handle(handle) {}

    UniqueHandle(const UniqueHandle&) = delete;

    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : m_handle(std::move(other.m_handle)) 
    {
        other.m_handle = nullptr;
    }

    UniqueHandle& operator=(UniqueHandle&& other) noexcept 
    {
        if (this != &other) 
        {
            Reset();
            m_handle = std::move(other.m_handle);
            other.m_handle = nullptr;
        }

        return *this;
    }


    ~UniqueHandle() 
    {
        Reset();
    }


    bool IsValid() const 
    {
        return m_handle.get() != nullptr && m_handle.get() != INVALID_HANDLE_VALUE && CheckAlignment(4);
    }


    T Get() const 
    {
        return m_handle.get();
    }


    void Reset() 
    {
        if (IsValid()) 
        {
            m_handle.reset();
        }
    }
};
