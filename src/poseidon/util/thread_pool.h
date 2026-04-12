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
    // 就绪检测函数：返回true表示任务可以执行
    using ReadyCheck = std::function<bool()>;

    // 构造函数，指定线程数量
    ThreadPool(size_t threads, bool enable_prepare = false);

    // 禁止拷贝构造和赋值操作
    ThreadPool(const ThreadPool &) = delete;
    ThreadPool &operator=(const ThreadPool &) = delete;

    // 析构函数，关闭线程池
    ~ThreadPool();

    // 添加任务到线程池，返回future以便获取结果
    template <class F, class... Args>
    auto enqueue(F &&f, Args &&...args) -> std::future<typename std::result_of<F(Args...)>::type>;

    // 预备队列提交：只有readyCheck()返回true才会执行
    template<class F, class... Args>
    auto enqueue_prepare(ReadyCheck readyCheck, F&& f, Args&&... args)
        -> std::future<typename std::result_of<F(Args...)>::type>;

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


private:
    // 预备队列项：就绪检测函数 + 任务
    struct PrepareTask {
        ReadyCheck check;
        std::function<void()> task;
    };

    std::vector<PrepareTask> prepare_tasks_;  // 预备队列
    std::mutex prepare_mtx_;                // 预备队列锁
    std::thread checker_thread_;            // 就绪检测线程
    std::atomic<bool> checker_stop_{false}; // 检测线程停止标记

    // 就绪检测线程函数
    void checker_loop();
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
inline ThreadPool::ThreadPool(size_t threads, bool enable_prepare) : stop_(false), active_tasks_(0)
{
    for (size_t i = 0; i < threads; ++i)
        workers.emplace_back(
            [this]
            {
                while (true)
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

    // 启动预备队列检测线程
    if (enable_prepare) {
        checker_thread_ = std::thread(&ThreadPool::checker_loop, this);
    }
}

// 检查预备队列，就绪就移入任务队列
inline void ThreadPool::checker_loop()
{
    while (!checker_stop_)
    {
        std::lock_guard<std::mutex> lck(prepare_mtx_);

        for (auto iter = prepare_tasks_.begin(); iter != prepare_tasks_.end();)
        {
            if (iter->check())
            {
                {
                    std::lock_guard<std::mutex> task_lck(queue_mutex_);
                    tasks.push(std::move(iter->task));
                }
                condition_.notify_one();
                iter = prepare_tasks_.erase(iter);
            }
            else
            {
                ++iter;
            }
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
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

// 提交到预备队列
template<class F, class... Args>
auto ThreadPool::enqueue_prepare(ReadyCheck readyCheck, F&& f, Args&&... args)
    -> std::future<typename std::result_of<F(Args...)>::type> {
    using ReturnType = typename std::result_of<F(Args...)>::type;
    auto task = std::make_shared<std::packaged_task<ReturnType()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );
    std::future<ReturnType> res = task->get_future();

    // 包装成预备任务
    PrepareTask pt;
    pt.check = std::move(readyCheck);
    pt.task = [task]() { (*task)(); };

    {
        std::lock_guard<std::mutex> lock(prepare_mtx_);
        prepare_tasks_.push_back(std::move(pt));
    }
    return res;
}

// 等待所有任务完成
inline void ThreadPool::wait_all()
{
    std::unique_lock<std::mutex> lock(queue_mutex_);
    complete_condition_.wait(lock, [this] { return tasks.empty() && active_tasks_ == 0; });
}
}  // namespace poseidon
