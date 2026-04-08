#pragma once

#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <vector>
namespace poseidon
{
class ThreadPool
{
public:
    // 构造函数，指定线程数量
    ThreadPool(size_t threads);

    // 禁止拷贝构造和赋值操作
    ThreadPool(const ThreadPool &) = delete;
    ThreadPool &operator=(const ThreadPool &) = delete;

    // 析构函数，关闭线程池
    ~ThreadPool();

    // 添加任务到线程池，返回future以便获取结果
    template <class F, class... Args>
    auto enqueue(F &&f, Args &&...args) -> std::future<typename std::result_of<F(Args...)>::type>;

    // 等待所有任务完成
    void wait_all();

private:
    // 工作线程
    std::vector<std::thread> workers;
    // 任务队列
    std::queue<std::function<void()>> tasks;

    // 同步机制
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

    ParallelGroup(const ParallelGroup &) = delete;
    ParallelGroup &operator=(const ParallelGroup &) = delete;

    ~ParallelGroup()
    {
        for (auto &future : futures_)
        {
            if (future.valid())
            {
                future.wait();
            }
        }
    }

    template <class F, class... Args>
    void go(F &&f, Args &&...args)
    {
        using return_type = typename std::result_of<F(Args...)>::type;
        static_assert(std::is_same<return_type, void>::value,
                      "ParallelGroup::go requires void-returning tasks");
        futures_.emplace_back(thread_pool_.enqueue(std::forward<F>(f), std::forward<Args>(args)...));
    }

    void wait()
    {
        for (auto &future : futures_)
        {
            if (future.valid())
            {
                future.get();
            }
        }
        futures_.clear();
    }

private:
    ThreadPool &thread_pool_;
    std::vector<std::future<void>> futures_;
};

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
                        condition_.wait(lock,
                                             [this] { return stop_ || !tasks.empty(); });

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
                        // 如果所有任务都完成了，通知wait_all
                        if (tasks.empty() && active_tasks_ == 0)
                        {
                            complete_condition_.notify_one();
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
