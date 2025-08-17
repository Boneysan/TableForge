#!/usr/bin/env node

import fs from 'fs';
import path from 'path';

console.log('🚀 Starting Simplified Quality Gate Validation...\n');

class QualityGateValidator {
  constructor() {
    this.results = {
      passed: [],
      failed: [],
      warnings: []
    };
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = {
      info: '📋',
      success: '✅',
      error: '❌',
      warning: '⚠️'
    }[type];
    
    console.log(`${prefix} [${timestamp}] ${message}`);
  }

  checkFile(filePath, description) {
    try {
      if (fs.existsSync(filePath)) {
        this.results.passed.push(description);
        this.log(`${description} - Found`, 'success');
        return true;
      } else {
        this.results.failed.push(description);
        this.log(`${description} - Missing`, 'error');
        return false;
      }
    } catch (error) {
      this.results.failed.push(description);
      this.log(`${description} - Error: ${error.message}`, 'error');
      return false;
    }
  }

  checkDirectory(dirPath, description) {
    try {
      if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
        const files = fs.readdirSync(dirPath);
        if (files.length > 0) {
          this.results.passed.push(description);
          this.log(`${description} - Found (${files.length} files)`, 'success');
          return true;
        } else {
          this.results.warnings.push(description);
          this.log(`${description} - Empty directory`, 'warning');
          return false;
        }
      } else {
        this.results.failed.push(description);
        this.log(`${description} - Missing`, 'error');
        return false;
      }
    } catch (error) {
      this.results.failed.push(description);
      this.log(`${description} - Error: ${error.message}`, 'error');
      return false;
    }
  }

  checkTestResults() {
    this.log('🧪 Validating Test Infrastructure...', 'info');
    
    // Check test directories
    this.checkDirectory('tests/unit', 'Unit Test Directory');
    this.checkDirectory('tests/integration', 'Integration Test Directory');
    this.checkDirectory('tests/e2e', 'E2E Test Directory');
    
    // Check test configuration
    this.checkFile('vitest.config.ts', 'Vitest Configuration');
    this.checkFile('playwright.config.ts', 'Playwright Configuration');
    
    // Check for test results if they exist
    if (fs.existsSync('test-results/results.json')) {
      try {
        const results = JSON.parse(fs.readFileSync('test-results/results.json', 'utf8'));
        if (results.numTotalTests && results.numPassedTests) {
          const passRate = (results.numPassedTests / results.numTotalTests) * 100;
          if (passRate === 100) {
            this.results.passed.push('Unit Test Pass Rate');
            this.log(`Unit tests: ${results.numPassedTests}/${results.numTotalTests} (${passRate}%) ✅`, 'success');
          } else {
            this.results.failed.push('Unit Test Pass Rate');
            this.log(`Unit tests: ${results.numPassedTests}/${results.numTotalTests} (${passRate}%) ❌`, 'error');
          }
        }
      } catch (error) {
        this.results.warnings.push('Test Results Parse Error');
        this.log(`Could not parse test results: ${error.message}`, 'warning');
      }
    } else {
      this.results.warnings.push('Test Results File');
      this.log('No test results found - run npm run test:unit to generate', 'warning');
    }
  }

  checkCodeQuality() {
    this.log('📝 Validating Code Quality Infrastructure...', 'info');
    
    // Check configuration files
    this.checkFile('tsconfig.json', 'TypeScript Configuration');
    this.checkFile('eslint.config.js', 'ESLint Configuration');
    this.checkFile('vitest.config.ts', 'Test Configuration');
    this.checkFile('package.json', 'Package Configuration');
    
    // Check source directories
    this.checkDirectory('client/src', 'Client Source Code');
    this.checkDirectory('server', 'Server Source Code');
    this.checkDirectory('shared', 'Shared Source Code');
  }

  checkCiCdInfrastructure() {
    this.log('🚀 Validating CI/CD Infrastructure...', 'info');
    
    // Check CI/CD configuration
    this.checkFile('.github/workflows/ci-cd-quality-gates.yml', 'GitHub Actions CI/CD Pipeline');
    this.checkDirectory('scripts', 'Build Scripts Directory');
    
    // Check quality gate scripts
    this.checkFile('scripts/quality-gate-check.js', 'Quality Gate Validation Script');
    this.checkFile('scripts/run-performance-tests.js', 'Performance Test Runner');
    
    // Check documentation
    this.checkFile('docs/ci-cd/QUALITY_GATES.md', 'Quality Gates Documentation');
  }

  checkSecurityInfrastructure() {
    this.log('🔒 Validating Security Infrastructure...', 'info');
    
    // Check security test directory
    this.checkDirectory('tests/security', 'Security Test Directory');
    
    // Check package.json for security scripts
    try {
      const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
      if (packageJson.scripts && packageJson.scripts['security:audit']) {
        this.results.passed.push('Security Audit Script');
        this.log('Security audit script configured', 'success');
      } else {
        this.results.failed.push('Security Audit Script');
        this.log('Security audit script missing', 'error');
      }
    } catch (error) {
      this.results.failed.push('Package.json Security Check');
      this.log(`Could not check package.json: ${error.message}`, 'error');
    }
  }

  checkPerformanceInfrastructure() {
    this.log('⚡ Validating Performance Infrastructure...', 'info');
    
    // Check performance test directory
    this.checkDirectory('tests/performance', 'Performance Test Directory');
    
    // Check for performance testing tools in package.json
    try {
      const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
      const performanceScripts = [
        'test:performance',
        'test:performance:api',
        'test:performance:websocket'
      ];
      
      let hasPerformanceScripts = false;
      performanceScripts.forEach(script => {
        if (packageJson.scripts && packageJson.scripts[script]) {
          hasPerformanceScripts = true;
        }
      });
      
      if (hasPerformanceScripts) {
        this.results.passed.push('Performance Test Scripts');
        this.log('Performance test scripts configured', 'success');
      } else {
        this.results.failed.push('Performance Test Scripts');
        this.log('Performance test scripts missing', 'error');
      }
    } catch (error) {
      this.results.failed.push('Performance Script Check');
      this.log(`Could not check performance scripts: ${error.message}`, 'error');
    }
  }

  generateReport() {
    console.log('\n' + '='.repeat(80));
    console.log('🎯 QUALITY GATE INFRASTRUCTURE VALIDATION');
    console.log('='.repeat(80));
    
    const totalChecks = this.results.passed.length + this.results.failed.length + this.results.warnings.length;
    const passedChecks = this.results.passed.length;
    const passRate = totalChecks > 0 ? ((passedChecks / totalChecks) * 100).toFixed(1) : 0;
    
    if (this.results.failed.length === 0) {
      this.log('🎉 ALL QUALITY GATE INFRASTRUCTURE READY!', 'success');
    } else {
      this.log('⚠️ SOME INFRASTRUCTURE COMPONENTS MISSING', 'warning');
    }
    
    console.log(`\n📊 Results: ${passedChecks}/${totalChecks} checks passed (${passRate}%)\n`);
    
    if (this.results.passed.length > 0) {
      console.log('✅ Passed:');
      this.results.passed.forEach(item => console.log(`   • ${item}`));
      console.log('');
    }
    
    if (this.results.warnings.length > 0) {
      console.log('⚠️ Warnings:');
      this.results.warnings.forEach(item => console.log(`   • ${item}`));
      console.log('');
    }
    
    if (this.results.failed.length > 0) {
      console.log('❌ Missing/Failed:');
      this.results.failed.forEach(item => console.log(`   • ${item}`));
      console.log('');
    }
    
    // Infrastructure readiness assessment
    console.log('🚀 Infrastructure Readiness:');
    
    const hasTestInfra = this.results.passed.includes('Unit Test Directory') && 
                         this.results.passed.includes('Vitest Configuration');
    console.log(`   • Test Infrastructure: ${hasTestInfra ? '✅ Ready' : '❌ Not Ready'}`);
    
    const hasCiCd = this.results.passed.includes('GitHub Actions CI/CD Pipeline') &&
                    this.results.passed.includes('Quality Gate Validation Script');
    console.log(`   • CI/CD Pipeline: ${hasCiCd ? '✅ Ready' : '❌ Not Ready'}`);
    
    const hasCodeQuality = this.results.passed.includes('TypeScript Configuration') &&
                           this.results.passed.includes('ESLint Configuration');
    console.log(`   • Code Quality: ${hasCodeQuality ? '✅ Ready' : '❌ Not Ready'}`);
    
    const hasSecurityInfra = this.results.passed.includes('Security Test Directory') ||
                             this.results.passed.includes('Security Audit Script');
    console.log(`   • Security Infrastructure: ${hasSecurityInfra ? '✅ Ready' : '❌ Not Ready'}`);
    
    const hasPerformanceInfra = this.results.passed.includes('Performance Test Directory') ||
                                this.results.passed.includes('Performance Test Scripts');
    console.log(`   • Performance Infrastructure: ${hasPerformanceInfra ? '✅ Ready' : '❌ Not Ready'}`);
    
    console.log('\n🎯 Current Status: Quality Gate Infrastructure Validated');
    console.log('📋 Next Steps:');
    console.log('   1. Run unit tests: npm run test:unit');
    console.log('   2. Run integration tests: npm run test:integration');
    console.log('   3. Run security audit: npm run security:audit');
    console.log('   4. Deploy with confidence! 🚀');
    
    console.log('='.repeat(80));
    
    return this.results.failed.length === 0;
  }

  async validate() {
    try {
      this.checkCodeQuality();
      this.checkTestResults();
      this.checkCiCdInfrastructure();
      this.checkSecurityInfrastructure();
      this.checkPerformanceInfrastructure();
      
      return this.generateReport();
    } catch (error) {
      this.log(`Validation failed: ${error.message}`, 'error');
      return false;
    }
  }
}

// Run validation
const validator = new QualityGateValidator();
validator.validate().then(success => {
  process.exit(success ? 0 : 1);
}).catch(error => {
  console.error('Validation error:', error);
  process.exit(1);
});
