# TableForge - Replit Import & Setup Guide

## 🚀 Quick Start for Replit

This guide helps you import and run the TableForge project in Replit with all Phase 1 Type Safety enhancements.

### 📋 Prerequisites

- Replit account
- Node.js 18+ (automatically provided in Replit)
- PostgreSQL database (Neon DB recommended)

### 🔧 Step 1: Import to Replit

1. **Import from GitHub:**
   ```
   https://github.com/Boneysan/TableForge
   ```

2. **Select Node.js template** when prompted

3. **Replit will automatically detect:**
   - `package.json` for dependencies
   - TypeScript configuration
   - Build scripts

### 📦 Step 2: Install Dependencies

Replit should auto-install, but if needed:

```bash
npm install
```

**Key Dependencies for Type Safety:**
- `typescript: 5.6.3` - TypeScript compiler
- `tsx: ^4.19.1` - TypeScript executor
- `@typescript-eslint/*` - TypeScript ESLint rules
- `vitest: ^3.2.4` - Testing framework

### 🔐 Step 3: Environment Setup

Create `.env` file (Replit Secrets tab):

```env
# Database
DATABASE_URL=your_postgresql_connection_string
DIRECT_URL=your_direct_database_connection

# Authentication
JWT_SECRET=your_jwt_secret_key
SESSION_SECRET=your_session_secret

# Firebase (optional)
FIREBASE_PROJECT_ID=your_firebase_project
FIREBASE_PRIVATE_KEY=your_firebase_private_key
FIREBASE_CLIENT_EMAIL=your_firebase_client_email

# Storage (optional)
GCS_BUCKET_NAME=your_gcs_bucket
GCS_PROJECT_ID=your_gcs_project

# Development
NODE_ENV=development
PORT=3000
```

### 🛠️ Step 4: Replit Configuration

**`.replit` file** (should be auto-created):
```toml
run = "npm run dev"
entrypoint = "server/index.ts"

[nix]
channel = "stable-22_11"

[deployment]
run = ["sh", "-c", "npm run build && npm start"]

[[ports]]
localPort = 3000
externalPort = 80

[env]
NODE_ENV = "development"
```

**`replit.nix` file** (for system dependencies):
```nix
{ pkgs }: {
  deps = [
    pkgs.nodejs-18_x
    pkgs.nodePackages.npm
    pkgs.nodePackages.typescript
    pkgs.postgresql
  ];
}
```

### 🎯 Step 5: Phase 1 Type Safety Validation

Run these commands in Replit Console to validate Phase 1:

```bash
# 1. Check TypeScript compilation
npm run type-check

# 2. Lint TypeScript code
npm run lint

# 3. Run Phase 1 status check
npm run phase1:status

# 4. Run type safety tests
npx tsx tests/unit/type-safety.test.ts

# 5. Simple validation (no dependencies)
node tests/unit/type-safety-simple.test.js
```

### 📁 Step 6: Project Structure Overview

```
TableForge/
├── 📋 Type Definitions (Phase 1 Complete)
│   ├── shared/types/
│   │   ├── api.ts           # API response types
│   │   ├── websocket.ts     # WebSocket event types
│   │   └── requests.ts      # Request types
│   ├── server/types/
│   │   └── database.ts      # Database query types
│   ├── server/middleware/
│   │   └── types.ts         # Middleware types
│   └── server/repositories/
│       └── types.ts         # Repository pattern types
│
├── 🧪 Tests & Validation
│   ├── tests/unit/
│   │   ├── type-safety.test.ts        # Full TypeScript tests
│   │   └── type-safety-simple.test.js # Simple Node.js tests
│   └── scripts/
│       ├── type-check.ts              # Type validation script
│       └── phase1-status.ts           # Phase 1 completion checker
│
├── 🚀 Application Code
│   ├── server/              # Backend (Express + TypeScript)
│   ├── client/              # Frontend (React + TypeScript)
│   └── shared/              # Shared utilities & types
│
└── 📚 Documentation
    └── docs/implementation/
        └── phase1-type-safety.md     # Complete Phase 1 guide
```

### 🔍 Step 7: Development Workflow

**Start Development Server:**
```bash
npm run dev
```

**Type Safety Checks:**
```bash
# Quick type check
npm run type-check

# Detailed type analysis
npm run type-check:detailed

# ESLint validation
npm run lint

# Auto-fix linting issues
npm run lint:fix
```

**Database Setup:**
```bash
# Push schema to database
npm run db:push
```

**Testing:**
```bash
# Run all tests
npm test

# Run type safety tests specifically
npx tsx tests/unit/type-safety.test.ts
```

### 🎨 Step 8: Replit-Specific Tips

**1. Console Access:**
- Use Replit Console (bottom panel) for commands
- Shell tab for full terminal access

**2. Environment Variables:**
- Use Secrets tab instead of `.env` file
- Secrets are automatically injected

**3. Database Connection:**
- Replit provides free PostgreSQL instances
- Or connect to external Neon/Supabase database

**4. Port Configuration:**
- Default port 3000 is auto-configured
- Replit handles port forwarding automatically

**5. Hot Reload:**
- TypeScript files auto-compile on save
- Server restarts automatically with `npm run dev`

### 🚨 Troubleshooting

**TypeScript Errors:**
```bash
# Clear TypeScript cache
rm -rf node_modules/.cache

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
```

**Port Issues:**
```bash
# Kill existing processes
pkill -f "node"
npm run dev
```

**Database Connection:**
```bash
# Test database connection
node -e "console.log(process.env.DATABASE_URL)"
```

### ✅ Phase 1 Validation Checklist

Run these commands to verify Phase 1 completion:

- [ ] `npm install` - Dependencies installed
- [ ] `npm run type-check` - TypeScript strict compilation passes
- [ ] `npm run lint` - ESLint validation passes
- [ ] `npm run phase1:status` - Phase 1 status shows 100% complete
- [ ] `npx tsx tests/unit/type-safety.test.ts` - All type safety tests pass
- [ ] `npm run dev` - Development server starts without errors

### 🎯 Expected Output

**Successful Phase 1 Setup:**
```
🧪 Running Phase 1 Type Safety Tests...

📋 Phase 1 Type Safety - API Response Types
  ✅ should create valid ApiResponse with typed data
  ✅ should create valid ErrorResponse
  ✅ should create valid PaginatedResponse

📋 Phase 1 Type Safety - Database Query Types
  ✅ should create valid successful QueryResult
  ✅ should create valid error QueryResult

📋 Phase 1 Type Safety - Repository Pattern
  ✅ should validate Repository interface structure

🎉 Phase 1 Type Safety Tests Complete!
✅ All core type definitions validated successfully
📊 TypeScript compilation ensures type safety at build time
```

### 🔗 Useful Replit Features

- **Version Control:** Built-in Git integration
- **Collaboration:** Real-time collaborative editing
- **Deployment:** One-click deployment to Replit hosting
- **Database:** Integrated PostgreSQL database option
- **Secrets Management:** Secure environment variable storage

### 📞 Support

If you encounter issues:

1. **Check Replit Console** for error messages
2. **Verify Environment Variables** in Secrets tab
3. **Run Phase 1 validation** commands above
4. **Check TypeScript compilation** with `npm run type-check`

---

**Ready to code!** 🚀 Your TableForge project with Phase 1 Type Safety is now fully configured for Replit development.
