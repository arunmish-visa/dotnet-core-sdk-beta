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
    /// card numbers, session tokens) in request/response DTOs. No raw XML or
    /// response body content is ever logged at any level — only metadata such as
    /// HTTP status codes, content lengths, type names, and error messages.
    /// </summary>
    public static class LogFactory
    {
        private static readonly object _lock = new object();
        private static volatile ILoggerFactory _loggerFactory;

        /// <summary>
        /// Allows consumers to inject their own ILoggerFactory for full control
        /// over log routing, sinks, and filtering levels.
        /// Thread-safe: uses volatile read + lock on write.
        /// </summary>
        /// <param name="loggerFactory">The ILoggerFactory to use for all SDK logging.</param>
        public static void SetLoggerFactory(ILoggerFactory loggerFactory)
        {
            lock (_lock)
            {
                _loggerFactory = loggerFactory;
            }
        }

        private static ILoggerFactory GetLoggerFactory()
        {
            // Volatile read — no lock needed for read path (double-checked pattern)
            var factory = _loggerFactory;
            if (factory != null)
                return factory;

            lock (_lock)
            {
                if (_loggerFactory == null)
                {
                    // Default: Warning level via Debug output (only captured when debugger is attached).
                    // Consumers should call SetLoggerFactory() to wire up their own sinks/levels.
                    _loggerFactory = new LoggerFactory().AddDebug(LogLevel.Warning);
                }
                return _loggerFactory;
            }
        }

        public static ILogger getLog(Type classType)
        {
            return GetLoggerFactory().CreateLogger(classType.FullName);
        }
    }
}
