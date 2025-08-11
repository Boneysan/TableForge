/**
 * API Documentation Server
 * 
 * Serves interactive API documentation using multiple formats:
 * - Swagger UI at /docs
 * - ReDoc at /docs/redoc
 * - Raw OpenAPI spec at /docs/openapi.json
 */

import { Express, Request, Response } from 'express';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import redocExpress from 'redoc-express';
import path from 'path';
import fs from 'fs';
import * as yaml from 'js-yaml';

// OpenAPI specification configuration
const swaggerOptions: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'Vorpal Board API',
      version: '1.0.0',
      description: `
        Comprehensive multiplayer virtual tabletop gaming platform API.
        
        ## Features
        - Real-time multiplayer game rooms
        - Asset management with Google Cloud Storage
        - Card and deck management system
        - WebSocket-based real-time communication
        - Firebase authentication
        - Comprehensive observability and metrics
        
        ## Authentication
        Most endpoints require Firebase ID token authentication via Bearer token in Authorization header.
        
        ## WebSocket Connection
        Real-time features are available via WebSocket connection at \`/ws\` endpoint with authentication.
        
        ## Rate Limiting
        All endpoints are rate-limited. See specific endpoint documentation for limits.
      `,
      contact: {
        name: 'Vorpal Board API Support',
        url: 'https://github.com/vorpal-board/api',
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT',
      },
    },
    servers: [
      {
        url: 'http://localhost:5000',
        description: 'Development server',
      },
      {
        url: 'https://{repl-url}.replit.dev',
        description: 'Replit deployment',
        variables: {
          'repl-url': {
            default: 'your-repl',
            description: 'Your Replit deployment URL',
          },
        },
      },
    ],
    components: {
      securitySchemes: {
        FirebaseAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Firebase ID token',
        },
        ReplitAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Replit authentication token',
        },
      },
    },
    security: [
      { FirebaseAuth: [] },
      { ReplitAuth: [] },
    ],
  },
  apis: [
    './server/routes.ts',
    './server/routes/*.ts',
    './server/docs/openapi.yaml',
  ],
};

// Load OpenAPI spec from YAML file
function loadOpenAPISpec(): any {
  try {
    const yamlPath = path.join(process.cwd(), 'server', 'docs', 'openapi.yaml');
    const yamlContent = fs.readFileSync(yamlPath, 'utf8');
    return yaml.load(yamlContent);
  } catch (error) {
    console.warn('Could not load OpenAPI YAML file, falling back to JSDoc generation:', (error as Error).message);
    return swaggerJsdoc(swaggerOptions);
  }
}

// Generate the OpenAPI specification
export const apiSpec = loadOpenAPISpec();

// Swagger UI configuration
const swaggerUiOptions = {
  customCss: `
    .swagger-ui .topbar { display: none; }
    .swagger-ui .info .title { color: #2563eb; }
    .swagger-ui .scheme-container { background: #f8fafc; }
    .swagger-ui .opblock.opblock-get { border-color: #10b981; }
    .swagger-ui .opblock.opblock-post { border-color: #3b82f6; }
    .swagger-ui .opblock.opblock-put { border-color: #f59e0b; }
    .swagger-ui .opblock.opblock-delete { border-color: #ef4444; }
  `,
  customSiteTitle: 'Vorpal Board API Documentation',
  customfavIcon: '/favicon.ico',
  swaggerOptions: {
    persistAuthorization: true,
    displayRequestDuration: true,
    filter: true,
    tryItOutEnabled: true,
    displayOperationId: false,
    defaultModelsExpandDepth: 2,
    defaultModelExpandDepth: 2,
    docExpansion: 'list',
    operationsSorter: 'alpha',
    tagsSorter: 'alpha',
  },
};

// ReDoc configuration
const redocOptions = {
  title: 'Vorpal Board API Documentation',
  theme: {
    colors: {
      primary: {
        main: '#2563eb',
      },
    },
    typography: {
      fontSize: '14px',
      lineHeight: '1.5',
      fontFamily: 'Inter, system-ui, sans-serif',
    },
  },
  hideDownloadButton: false,
  hideLoading: false,
  nativeScrollbars: false,
  disableSearch: false,
  expandResponses: '200,201',
  jsonSampleExpandLevel: 2,
  hideSingleRequestSampleTab: true,
  menuToggle: true,
  pathInMiddlePanel: true,
  requiredPropsFirst: true,
  sortPropsAlphabetically: true,
  payloadSampleIdx: 0,
};

/**
 * Setup API documentation routes
 */
export function setupApiDocs(app: Express): void {
  console.log('📚 [API Docs] Setting up API documentation routes...');

  // Serve raw OpenAPI specification as JSON
  app.get('/docs/openapi.json', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(apiSpec);
  });

  // Serve raw OpenAPI specification as YAML
  app.get('/docs/openapi.yaml', (req: Request, res: Response) => {
    try {
      const yamlContent = yaml.dump(apiSpec, { 
        indent: 2,
        lineWidth: -1,
        noRefs: true,
        skipInvalid: true,
      });
      res.setHeader('Content-Type', 'text/yaml');
      res.send(yamlContent);
    } catch (error) {
      res.status(500).json({ error: 'Failed to convert spec to YAML' });
    }
  });

  // Health check for API docs
  app.get('/docs/health', (req: Request, res: Response) => {
    res.json({
      service: 'vorpal-board-docs',
      status: 'healthy',
      version: '1.0.0',
      endpoints: {
        swagger: '/docs',
        redoc: '/docs/redoc',
        openapi_json: '/docs/openapi.json',
        openapi_yaml: '/docs/openapi.yaml',
      },
      timestamp: new Date().toISOString(),
    });
  });

  // ReDoc documentation
  app.get('/docs/redoc', (req: Request, res: Response) => {
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Vorpal Board API - ReDoc</title>
          <meta charset="utf-8"/>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
          <style>
            body { margin: 0; padding: 0; }
          </style>
        </head>
        <body>
          <redoc spec-url="${req.protocol}://${req.get('host')}/docs/openapi.json"></redoc>
          <script src="https://cdn.jsdelivr.net/npm/redoc@2.1.3/bundles/redoc.standalone.js"></script>
        </body>
      </html>
    `;
    res.send(html);
  });

  // Swagger UI documentation (main docs route)
  app.use('/docs', swaggerUi.serve);
  app.get('/docs', swaggerUi.setup(apiSpec, swaggerUiOptions));

  // Documentation landing page with links to different formats
  app.get('/docs/index', (req: Request, res: Response) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vorpal Board API Documentation</title>
        <style>
          body {
            font-family: Inter, system-ui, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            background-color: #f8fafc;
          }
          .header {
            text-align: center;
            margin-bottom: 3rem;
            padding: 2rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          }
          .header h1 {
            color: #2563eb;
            margin: 0;
            font-size: 2.5rem;
          }
          .header p {
            color: #64748b;
            margin-top: 0.5rem;
            font-size: 1.1rem;
          }
          .docs-grid {
            display: grid;
            gap: 1.5rem;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          }
          .doc-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
          }
          .doc-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
          }
          .doc-card h3 {
            color: #1e293b;
            margin-top: 0;
            margin-bottom: 0.5rem;
          }
          .doc-card p {
            color: #64748b;
            margin-bottom: 1rem;
          }
          .doc-card a {
            display: inline-block;
            background: #2563eb;
            color: white;
            padding: 0.5rem 1rem;
            text-decoration: none;
            border-radius: 4px;
            font-weight: 500;
            transition: background-color 0.2s;
          }
          .doc-card a:hover {
            background: #1d4ed8;
          }
          .raw-links {
            margin-top: 2rem;
            padding: 1.5rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          }
          .raw-links h3 {
            margin-top: 0;
            color: #1e293b;
          }
          .raw-links a {
            display: inline-block;
            margin-right: 1rem;
            margin-bottom: 0.5rem;
            color: #2563eb;
            text-decoration: none;
            padding: 0.25rem 0.5rem;
            border: 1px solid #2563eb;
            border-radius: 4px;
            font-size: 0.9rem;
          }
          .raw-links a:hover {
            background: #2563eb;
            color: white;
          }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>🎲 Vorpal Board API</h1>
          <p>Comprehensive multiplayer virtual tabletop gaming platform</p>
        </div>

        <div class="docs-grid">
          <div class="doc-card">
            <h3>📖 Interactive Documentation (Swagger UI)</h3>
            <p>
              Full interactive API documentation with request/response examples.
              Test endpoints directly from your browser with built-in authentication.
            </p>
            <a href="${baseUrl}/docs">Open Swagger UI</a>
          </div>

          <div class="doc-card">
            <h3>📚 Reference Documentation (ReDoc)</h3>
            <p>
              Clean, readable API reference documentation with detailed schemas
              and comprehensive endpoint descriptions.
            </p>
            <a href="${baseUrl}/docs/redoc">Open ReDoc</a>
          </div>

          <div class="doc-card">
            <h3>🔗 WebSocket Documentation</h3>
            <p>
              Real-time communication protocols for multiplayer gaming features.
              Connect at <code>/ws</code> with authentication.
            </p>
            <a href="#websocket">View WebSocket Docs</a>
          </div>

          <div class="doc-card">
            <h3>📊 Observability Dashboard</h3>
            <p>
              System health, metrics, and monitoring endpoints.
              Production-ready observability with Prometheus integration.
            </p>
            <a href="${baseUrl}/api/observability/status">View System Status</a>
          </div>
        </div>

        <div class="raw-links">
          <h3>Raw API Specifications</h3>
          <a href="${baseUrl}/docs/openapi.json">OpenAPI JSON</a>
          <a href="${baseUrl}/docs/openapi.yaml">OpenAPI YAML</a>
          <a href="${baseUrl}/docs/health">Documentation Health</a>
          <a href="${baseUrl}/api/observability/metrics">Prometheus Metrics</a>
        </div>

        <div id="websocket" style="margin-top: 2rem; padding: 1.5rem; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
          <h3>🔗 WebSocket Connection</h3>
          <p><strong>Endpoint:</strong> <code>ws://localhost:5000/ws</code> (development)</p>
          <p><strong>Authentication:</strong> Include Firebase ID token in connection headers</p>
          <p><strong>Events:</strong> Real-time room updates, card moves, chat messages, dice rolls</p>
        </div>
      </body>
      </html>
    `);
  });

  console.log('✅ [API Docs] Documentation routes configured:');
  console.log('  📖 Swagger UI: /docs');
  console.log('  📚 ReDoc: /docs/redoc');
  console.log('  📋 Landing: /docs/index');
  console.log('  📄 OpenAPI JSON: /docs/openapi.json');
  console.log('  📄 OpenAPI YAML: /docs/openapi.yaml');
  console.log('  ❤️  Health: /docs/health');
}

export default setupApiDocs;