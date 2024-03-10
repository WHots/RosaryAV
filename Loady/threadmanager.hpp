#pragma once
#include <thread>
#include <functional>
#include <atomic>










class ThreadManager 
{


public:

    struct Task 
    {
        std::function<void(DWORD)> func;
        DWORD pid;

        Task(std::function<void(DWORD)> func, DWORD pid) : func(func), pid(pid) {}
    };

    template <typename Func, typename ...Args>
    void addTask(Func&& func, Args&&... args) { tasks_.emplace_back(std::forward<Func>(func), std::forward<Args>(args)...); }


    void LaunchAll() 
    {
        for (auto& task : tasks_) 
        {
            activeThreadCount_++;
            threads_.emplace_back(std::thread(std::bind(task.func, task.pid)));
        }
        tasks_.clear();
    }


    void JoinAll() 
    {
        for (auto& thread : threads_) 
        {
            if (thread.joinable()) 
                thread.join();           
        }

        activeThreadCount_ = 0;
    }


    size_t GetActiveThreadCount() const 
    {
        return activeThreadCount_;
    }


private:

    std::vector<Task> tasks_;
    std::vector<std::thread> threads_;
    std::atomic<size_t> activeThreadCount_ = 0;
};