import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { config } from "./configLoader";
import { 
  createRateLimiter, 
  createApiRateLimiter, 
  createAuthRateLimiter,
  createSecurityHeaders,
  securityLogger,
  healthCheck
} from "./middleware";
import { logger, healthCheck as loggerHealthCheck } from "./utils/logger";
import { errorHandler, addCorrelationId, setupGlobalErrorHandlers } from "./middleware/errorHandler";

const app = express();

// Setup global error handlers
setupGlobalErrorHandlers();

// Correlation ID middleware (first)
app.use(addCorrelationId);

// Security middleware
const { cors: corsMiddleware, helmet: helmetMiddleware } = createSecurityHeaders();
app.use(helmetMiddleware);
app.use(corsMiddleware);
app.use(securityLogger);

// Rate limiting
app.use('/', createRateLimiter());
app.use('/api', createApiRateLimiter());
app.use('/api/auth', createAuthRateLimiter());

// Body parsing with size limits
app.use(express.json({ limit: `${config.MAX_FILE_SIZE}b` }));
app.use(express.urlencoded({ extended: false, limit: `${config.MAX_FILE_SIZE}b` }));

// Health check endpoint
app.get('/health', healthCheck);

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  const server = await registerRoutes(app);

  // Use comprehensive error handling middleware
  app.use(errorHandler);

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // Use validated configuration for port
  server.listen({
    port: config.PORT,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${config.PORT}`);
    logger.info("🚀 Server started successfully", { 
      port: config.PORT,
      environment: process.env.NODE_ENV,
      version: process.env.npm_package_version 
    });
    loggerHealthCheck('server', 'healthy');
  });
})();
