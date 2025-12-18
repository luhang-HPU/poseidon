#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream> 
#include <chrono>
#include <vector>
#include "poseidon/plaintext.h"

namespace poseidon {
namespace util {

class Logger {
public:
    // 1. 日志级别枚举
    enum Level {
        DEBUG = 0,
        INFO,
        WARN,
        ERROR
    };

    // --- 计时功能 ---
    class ScopeTimer {
    public:
        ScopeTimer(const std::string& name, Level level = INFO);
        ~ScopeTimer();
    private:
        std::string m_name;
        Level m_level;
        std::chrono::high_resolution_clock::time_point m_start;
    };

    // 2. 获取单例实例的方法
    static Logger& getInstance();

    // 3. 设置日志文件路径
    void setLogFile(const std::string& filename);

    // 4. 设置最低日志级别
    void setLevel(Level level);

    // 5. 核心日志写入方法
    void log(Level level, const std::string& message);

    // 添加这个公共方法用于宏中的级别检查
    Level getCurrentLevel() const {
        return m_currentLevel;
    }

    // --- 新增的 vector<int> 输出方法 ---
     // --- 模板实现：允许任何类型的向量 ---
    template <typename T>
    void logVector(const std::string& description, const std::vector<T>& data) {
        
        const Level level = INFO; 

        std::stringstream ss;
        ss << description << " [Size: " << data.size() << "] {";

        const int elementsPerLine = 32768; 
        
        for (size_t i = 0; i < data.size(); ++i) {
            ss << data[i]; // T 类型必须支持 << 操作符
            
            if (i < data.size() - 1) {
                ss << ", ";
            }
            
            if ((i + 1) % elementsPerLine == 0 && i < data.size() - 1) {
                ss << "\n    "; 
            }
        }
        ss << "}";

        // 调用核心日志方法
        this->log(level, ss.str()); // log 方法假设接收 std::string
    }

    void logPlainCoeff(const std::string& description, const Plaintext& plain) {
        
        const Level level = INFO; 

        std::stringstream ss;
        ss << description << " [Size: " << plain.coeff_count() << "] {";

        const int elementsPerLine = 32768; 
        
        for (size_t i = 0; i < plain.coeff_count(); ++i) {
            ss << plain[i]; // T 类型必须支持 << 操作符
            
            if (i < plain.coeff_count() - 1) {
                ss << ", ";
            }
            
            if ((i + 1) % elementsPerLine == 0 && i < plain.coeff_count() - 1) {
                ss << "\n    "; 
            }
        }
        ss << "}";

        // 调用核心日志方法
        this->log(level, ss.str()); // log 方法假设接收 std::string
    }
    
private:
    // 私有构造函数、析构函数和拷贝赋值，实现单例模式
    Logger();
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::ofstream m_logFile;       // 日志文件输出流
    std::mutex m_mutex;            // 保护共享资源的互斥锁
    Level m_currentLevel = INFO;   // 当前最低日志级别

    // 辅助函数：获取时间戳字符串
    std::string getCurrentTime();

    // 辅助函数：将日志级别转换为字符串
    std::string levelToString(Level level);
};

// 核心封装宏：将输入流导入到临时的 std::stringstream 中
// 宏参数 ...msg 捕获所有流式输入
#define LOG_STREAM(LEVEL, msg) \
    do { \
        if (LEVEL >= Logger::getInstance().getCurrentLevel()) { /* 可选：预检查级别 */ \
            std::stringstream ss; \
            ss << msg; \
            Logger::getInstance().log(LEVEL, ss.str()); \
        } \
    } while(0)

// 7. 方便调用的宏
#define LOG_DEBUG(msg) LOG_STREAM(Logger::DEBUG, msg)
#define LOG_INFO(msg)  LOG_STREAM(Logger::INFO, msg)
#define LOG_WARN(msg)  LOG_STREAM(Logger::WARN, msg)
#define LOG_ERROR(msg) LOG_STREAM(Logger::ERROR, msg)

// 使用临时变量来确保 ScopeTimer 可以在代码块内创建和销毁
#define LOG_SCOPE_TIMER(name) \
    poseidon::util::Logger::ScopeTimer timer_##__LINE__(name);

}

#define CHRONO_START_POINT(name) auto name##_start = std::chrono::high_resolution_clock::now();

#define CHRONO_END_POINT(name, description, level) \
    auto name##_end = std::chrono::high_resolution_clock::now(); \
    auto name##_duration = std::chrono::duration_cast<std::chrono::microseconds>(name##_end - name##_start); \
    double name##_seconds = name##_duration.count() / 1000000.0; \
    LOG_INFO(description << " finished. Elapsed time: " \
             << std::fixed << std::setprecision(3) << name##_seconds << " s (" \
             << name##_duration.count() << " us)");
}