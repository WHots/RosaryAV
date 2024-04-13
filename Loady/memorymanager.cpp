#include "memorymanager.hpp"





template <typename T>
bool UniqueHandle<T>::CheckAlignment(size_t alignment) const 
{

    void* ptr = static_cast<void*>(m_handle.get());
    void* alignedPtr;
    size_t alignmentOffset;

    if (std::align(alignment, sizeof(T), alignedPtr, alignmentOffset)) 
    {
        return ptr == alignedPtr;
    }

    return false;
}


template class UniqueHandle<HANDLE>;