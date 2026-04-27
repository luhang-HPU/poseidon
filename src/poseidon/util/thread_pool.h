#pragma once

#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <vector>
namespace poseidon
{
class ThreadPool
{
public:
    static ThreadPool &get_instance();
    explicit ThreadPool(size_t threads);

    ThreadPool(const ThreadPool &) = delete;
    ThreadPool &operator=(const ThreadPool &) = delete;
    ~ThreadPool();
    size_t get_thread_count() const { return workers.size(); }

    template <class F, class... Args>
    auto enqueue(F &&f, Args &&...args) -> std::future<typename std::result_of<F(Args...)>::type>;
    void wait_all();
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::condition_variable complete_condition_;
    bool stop_;
    size_t active_tasks_;
};

class ParallelGroup
{
public:
    explicit ParallelGroup(ThreadPool &thread_pool) : thread_pool_(thread_pool) {}

    template <class F, class... Args>
    void go(F &&f, Args &&...args)
    {
        futures_.emplace_back(thread_pool_.enqueue(std::forward<F>(f), std::forward<Args>(args)...));
    }

    void wait()
    {
        for (auto &future : futures_)
        {
            future.get();
        }
        futures_.clear();
    }

private:
    ThreadPool &thread_pool_;
    std::vector<std::future<void>> futures_;
};

inline ThreadPool &ThreadPool::get_instance()
{
    static ThreadPool instance(
        []()
        {
            unsigned int hardware_threads = std::thread::hardware_concurrency();
            return (hardware_threads > 0) ? hardware_threads : 4;
        }());
    return instance;
}


// 构造函数：创建指定数量的工作线程
inline ThreadPool::ThreadPool(size_t threads) : stop_(false), active_tasks_(0)
{
    for (size_t i = 0; i < threads; ++i)
        workers.emplace_back(
            [this]
            {
                for (;;)
                {
                    std::function<void()> task;

                    {
                        std::unique_lock<std::mutex> lock(queue_mutex_);
                        condition_.wait(lock, [this] { return stop_ || !tasks.empty(); });

                        if (stop_ && tasks.empty())
                            return;

                        task = std::move(tasks.front());
                        tasks.pop();
                        active_tasks_++;
                    }

                    // 执行任务
                    task();
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex_);
                        active_tasks_--;
                        if (tasks.empty() && active_tasks_ == 0)
                        {
                            complete_condition_.notify_all();
                        }
                    }
                }
            });
}

// 析构函数：停止所有工作线程
inline ThreadPool::~ThreadPool()
{
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_ = true;
    }
    condition_.notify_all();
    for (std::thread &worker : workers)
        worker.join();
}

// 向线程池添加任务
template <class F, class... Args>
auto ThreadPool::enqueue(F &&f, Args &&...args)
    -> std::future<typename std::result_of<F(Args...)>::type>
{

    using return_type = typename std::result_of<F(Args...)>::type;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...));

    std::future<return_type> res = task->get_future();
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);

        // 如果线程池已经停止，不能添加新任务
        if (stop_)
            throw std::runtime_error("enqueue on stopped ThreadPool");

        tasks.emplace([task]() { (*task)(); });
    }
    condition_.notify_one();
    return res;
}

// 等待所有任务完成
inline void ThreadPool::wait_all()
{
    std::unique_lock<std::mutex> lock(queue_mutex_);
    complete_condition_.wait(lock, [this] { return tasks.empty() && active_tasks_ == 0; });
}
}  // namespace poseidon
