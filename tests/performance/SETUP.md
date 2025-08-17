# Performance Testing Package Requirements

## Required Dependencies

To run the performance tests, install the following packages:

### Core Performance Testing
```bash
# k6 load testing tool (system installation)
# Windows (Chocolatey)
choco install k6

# macOS (Homebrew) 
brew install k6

# Linux (Ubuntu/Debian)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

### API Performance Testing Dependencies
```bash
# Install autocannon for API benchmarking
npm install --save-dev autocannon
npm install --save-dev @types/autocannon

# Install additional Vitest dependencies
npm install --save-dev vitest @vitest/ui
```

### TypeScript Configuration
Ensure your `tsconfig.json` includes the performance test directories:

```json
{
  "include": [
    "tests/performance/**/*"
  ],
  "compilerOptions": {
    "types": ["vitest/globals", "node"]
  }
}
```

## Usage

### k6 WebSocket Load Testing
```bash
k6 run tests/performance/load/websocket-load.js
```

### API Performance Testing
```bash
npm run test tests/performance/api/
```
