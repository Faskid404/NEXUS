import pino from "pino";

const isProduction = process.env.NODE_ENV === "production";

export const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  redact: [
    "req.headers.authorization",
    "req.headers.cookie",
    "res.headers['set-cookie']",
    "*.password",
    "*.token",
    "*.secret",
  ],
  ...(isProduction
    ? {}
    : {
        transport: {
          target: "pino-pretty",
          options: { colorize: true },
        },
      }),
});

/**
 * Create a child logger with a fixed component context.
 * Use this in individual modules so every log line carries its origin.
 *
 * @example
 *   const log = createLogger("scanner");
 *   log.info({ host, port }, "Port open");
 */
export function createLogger(component: string, extra?: Record<string, unknown>): pino.Logger {
  return logger.child({ component, ...extra });
}

/**
 * Create a per-request correlation logger.
 * Attach to a request so all downstream calls carry the same requestId.
 */
export function createRequestLogger(requestId: string, component?: string): pino.Logger {
  return logger.child({ requestId, ...(component ? { component } : {}) });
}
