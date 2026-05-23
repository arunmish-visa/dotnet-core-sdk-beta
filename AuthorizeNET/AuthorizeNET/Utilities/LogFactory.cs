namespace AuthorizeNet.Utilities
{
    using System;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Factory for creating SDK loggers. Consumers can inject their own ILoggerFactory
    /// via SetLoggerFactory() to control log routing, sinks, and levels.
    /// 
    /// SECURITY NOTE: The default log level is Warning (not Debug) to prevent
    /// accidental exposure of sensitive data (merchantAuthentication credentials,
    /// card numbers, session tokens) in request/response DTOs. If you need Debug-level
    /// SDK logging during development, call LogFactory.SetLoggerFactory(...) with your
    /// own factory configured at the desired level, and ensure sensitive fields are
    /// redacted before they reach persistent log sinks.
    /// </summary>
    public static class LogFactory
    {
        private static ILoggerFactory _loggerFactory;

        /// <summary>
        /// Allows consumers to inject their own ILoggerFactory for full control
        /// over log routing, sinks, and filtering levels.
        /// </summary>
        /// <param name="loggerFactory">The ILoggerFactory to use for all SDK logging.</param>
        public static void SetLoggerFactory(ILoggerFactory loggerFactory)
        {
            _loggerFactory = loggerFactory;
        }

        private static ILoggerFactory GetLoggerFactory()
        {
            // Default: Warning level via Debug output (only captured when debugger is attached).
            // Consumers should call SetLoggerFactory() to wire up their own sinks/levels.
            return _loggerFactory ?? new LoggerFactory().AddDebug(LogLevel.Warning);
        }

        public static ILogger getLog(Type classType)
        {
            return GetLoggerFactory().CreateLogger(classType.FullName);
        }
    }
}
