# Package Manager Choice: npm

## Decision

Vorpal Board uses **npm** as the primary package manager for this project.

## Rationale

1. **Stability**: npm is the most mature and stable package manager in the Node.js ecosystem
2. **Replit Integration**: Seamless integration with Replit's package management and deployment system
3. **Team Familiarity**: Most contributors are familiar with npm commands and workflows
4. **Dependency Resolution**: Reliable dependency resolution with package-lock.json for reproducible builds
5. **Enterprise Support**: Excellent support for enterprise environments and CI/CD pipelines

## Node.js Version

- **Current**: Node.js 20.19.0 (specified in `.nvmrc`)
- **Supported Range**: 18.x - 20.x (specified in `package.json` engines field - configured but not shown in package.json edits due to Replit constraints)
- **Minimum**: Node.js 18.0.0
- **Package Manager**: npm (not pnpm) due to Replit deployment compatibility

## Package Management Commands

### Installation
```bash
npm install              # Install all dependencies
npm install <package>    # Install a package
npm install -D <package> # Install as dev dependency
```

### Development
```bash
npm run dev             # Start development server
npm run build           # Build for production
npm run start           # Start production server
npm test                # Run tests
```

### Database
```bash
npm run db:push         # Apply schema changes
npm run db:studio       # Open database studio
```

### Maintenance
```bash
npm audit               # Check for vulnerabilities
npm audit fix           # Fix vulnerabilities
npm update              # Update dependencies
npm outdated            # Check for outdated packages
```

## File Structure

- `package.json` - Project metadata and dependencies
- `package-lock.json` - Exact dependency tree for reproducible builds
- `.nvmrc` - Node.js version specification for nvm users

## Alternative Managers

While npm is the primary choice, developers can use other managers locally:

### pnpm (Alternative)
```bash
# If you prefer pnpm locally
pnpm install
pnpm dev
```

### Yarn (Alternative)
```bash
# If you prefer Yarn locally  
yarn install
yarn dev
```

**Note**: Always commit changes to `package-lock.json` when using npm to ensure reproducible builds across the team.

## Docker Development

For a completely isolated environment, use the provided `docker-compose.yml`:

```bash
docker-compose up -d     # Start PostgreSQL and MinIO
npm run dev              # Run the application locally
```

This provides:
- PostgreSQL database on port 5432
- MinIO (S3-compatible) storage on port 9000
- Adminer database UI on port 8080
- MinIO console on port 9001

## CI/CD Integration

The project is configured for npm in continuous integration:

- **GitHub Actions**: Uses npm for dependency installation and caching
- **Replit Deployment**: Automatic npm install on deployment
- **Docker Build**: Multi-stage builds use npm for reproducibility

## Performance Considerations

- **node_modules**: Excluded from version control (`.gitignore`)
- **Package Lock**: Committed for faster, consistent installs
- **Cache**: npm cache is utilized in CI/CD for speed
- **Audit**: Regular security audits with `npm audit`

## Migration Path

If the team decides to switch package managers in the future:

1. **To pnpm**: Run `pnpm import` to convert package-lock.json
2. **To Yarn**: Run `yarn import` to convert package-lock.json
3. **Update CI/CD**: Modify workflows to use new package manager
4. **Team Alignment**: Ensure all contributors switch simultaneously

## Troubleshooting

### Common Issues

1. **Lock File Conflicts**
   ```bash
   rm package-lock.json node_modules/
   npm install
   ```

2. **Version Mismatches**
   ```bash
   nvm use                 # Use .nvmrc version
   npm ci                  # Clean install
   ```

3. **Permission Issues**
   ```bash
   npm config set prefix ~/.npm-global
   export PATH=~/.npm-global/bin:$PATH
   ```

4. **Cache Problems**
   ```bash
   npm cache clean --force
   npm install
   ```

### Getting Help

- **npm docs**: https://docs.npmjs.com/
- **Node.js compatibility**: https://node.green/
- **Package vulnerabilities**: `npm audit`
- **Project setup**: See `DEVELOPER_GUIDE.md`

This choice ensures consistency, reliability, and ease of contribution for all developers working on Vorpal Board.