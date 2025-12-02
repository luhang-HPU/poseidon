#include "Logger.h"

namespace poseidon {
namespace util {

// 获取当前时间字符串 (格式: YYYY-MM-DD HH:MM:SS)
std::string Logger::getCurrentTime() {
    auto now = std::time(nullptr);
    auto localTime = *std::localtime(&now);
    
    std::stringstream ss;
    ss << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// 将日志级别转换为字符串
std::string Logger::levelToString(Level level) {
    switch (level) {
        case DEBUG: return "DEBUG";
        case INFO:  return "INFO "; // 保持对齐
        case WARN:  return "WARN "; // 保持对齐
        case ERROR: return "ERROR";
        default:    return "UNKNOWN";
    }
}

/**
 * 构造函数：记录开始时间
 * @param name 计时器的名称/描述
 * @param level 日志级别 (默认为 INFO)
 */
Logger::ScopeTimer::ScopeTimer(const std::string& name, Level level) 
    : m_name(name), m_level(level), m_start(std::chrono::high_resolution_clock::now()) 
{
    // 可选：记录计时器开始
    Logger::getInstance().log(DEBUG, "Timer '" + m_name + "' started.");
}

/**
 * 析构函数：计算并记录经过的时间
 */
Logger::ScopeTimer::~ScopeTimer() 
{
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - m_start);
    
    // 格式化输出：将微秒转换为毫秒和秒
    double seconds = duration.count() / 1000000.0;
    
    std::stringstream ss;
    ss << "Timer '" << m_name << "' finished. Elapsed time: " 
       << std::fixed << std::setprecision(3) << seconds << " s (" 
       << duration.count() << " us)";

    // 调用 Logger 核心方法记录结果
    Logger::getInstance().log(m_level, ss.str());
}

// ------------------- Logger 类实现 -------------------

// 私有构造函数：初始化日志文件流（默认输出到控制台）
Logger::Logger() {
    // 默认不打开文件，只输出到控制台。若调用 setLogFile 才会写入文件。
    std::cout << "Logger initialized." << std::endl;
}

// 析构函数：关闭文件流
Logger::~Logger() {
    if (m_logFile.is_open()) {
        m_logFile.close();
    }
    std::cout << "Logger shut down." << std::endl;
}

// 1. 获取单例实例
Logger& Logger::getInstance() {
    // C++11 局部静态变量的初始化是线程安全的
    static Logger instance;
    return instance;
}

// 2. 设置日志文件路径
void Logger::setLogFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // 如果已有文件打开，则先关闭
    if (m_logFile.is_open()) {
        m_logFile.close();
    }
    
    // 打开新的文件，使用 std::ios::app (追加模式)
    m_logFile.open(filename, std::ios::app);
    
    if (m_logFile.is_open()) {
        std::cout << "Log file set to: " << filename << std::endl;
    } else {
        std::cerr << "ERROR: Could not open log file: " << filename << std::endl;
    }
}

// 3. 设置最低日志级别
void Logger::setLevel(Level level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_currentLevel = level;
    std::cout << "Log level set to: " << levelToString(level) << std::endl;
}

// 4. 核心日志写入方法
void Logger::log(Level level, const std::string& message) {
    // 检查：如果当前级别低于设定的最低级别，则不记录
    if (level < m_currentLevel) {
        return;
    }

    // 格式化日志消息
    std::string formattedMessage = 
        "[" + getCurrentTime() + "] " +
        "[" + levelToString(level) + "] " +
        message;

    // 线程安全地写入
    std::lock_guard<std::mutex> lock(m_mutex);

    // 1. 写入到控制台 (根据级别可以区分颜色，但这里简化为只输出)
    if (level >= ERROR) {
        std::cerr << formattedMessage << std::endl;
    } else {
        std::cout << formattedMessage << std::endl;
    }

    // 2. 写入到文件
    if (m_logFile.is_open()) {
        m_logFile << formattedMessage << std::endl;
    }
}


}
}