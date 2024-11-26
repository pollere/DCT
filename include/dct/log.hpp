/**
 * DCT logger stub implementation.
 *
 * To define a custom logger, the application must implement dct::Logger
 * and call global_logger to set the logger implementation.
 */

#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <source_location>

#include <dct/format.hpp>

namespace {
    /// Compile-time evalute basename from full file path
    consteval const char* log_basename_(const char* path) {
        const char* last = nullptr;
        for (const char* current = path; *current != '\0'; ++current)
            if (*current == '/' || *current == '\\') last = current;
        return last ? last + 1 : path;
    }
}

namespace dct
{
    enum class log_level_t { L_TRACE, L_DEBUG, L_INFO, L_WARN, L_ERROR, L_FATAL };
    static const char* log_level_str[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" }; // needs same order
    using enum log_level_t;

    /// Logger implementation interface
    class Logger {
    public:
        virtual void log(
            log_level_t level,
            const std::source_location src,
            const char* basename,
            std::string statement
        ) = 0;

    public:
        Logger() = default;
        Logger(const Logger&) = delete;
        Logger(Logger&&) = delete;
        Logger& operator=(const Logger&) = delete;
        Logger& operator=(Logger&&) = delete;
        virtual ~Logger() = default;
    };

    /// Default Logger implementation
    class DefaultLogger : public Logger {
    public:
        log_level_t min_level = L_INFO;

        inline void log(
            log_level_t level,
            const std::source_location src,
            const char* basename,
            std::string statement
        ) {
            if (level < min_level) return;
            fmt::print(stderr, "{} [{}] {} (dct:{}:{}:{})\n",
                std::chrono::system_clock::now(),
                log_level_str[static_cast<size_t>(level)],
                statement,
                basename,
                src.line(),
                src.column());
        }
    };

    /// Get or set the global DCT logger
    inline Logger* global_logger(std::unique_ptr<Logger> set_to = nullptr) {
        static std::unique_ptr<Logger> logger = std::make_unique<DefaultLogger>(); // singleton
        if (set_to) logger = std::move(set_to);
        return logger.get();
    }

    consteval auto log(log_level_t level, const std::source_location src = std::source_location::current()) {
        const char* basename = log_basename_(src.file_name());
        return [=]<typename... T>(fmt::format_string<T...> fmt, T&&... args) constexpr -> void {
            dct::global_logger()->log(level, src, basename, fmt::format(fmt, std::forward<T>(args)...));
        };
    }
} // namespace dct
