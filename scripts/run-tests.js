#!/usr/bin/env node

/**
 * Comprehensive Test Runner - Phase 2 Week 4 
 * Orchestrates performance and security testing pipeline
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class TestRunner {
  constructor() {
    this.reportDir = path.join(__dirname, '../reports');
    this.timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    this.testResults = {
      timestamp: this.timestamp,
      summary: {},
      performance: {},
      security: {},
      unit: {},
      integration: {},
      e2e: {}
    };
    
    this.ensureReportDirectory();
  }

  ensureReportDirectory() {
    if (!fs.existsSync(this.reportDir)) {
      fs.mkdirSync(this.reportDir, { recursive: true });
    }
  }

  async runAllTests() {
    console.log('🚀 Starting comprehensive test suite...\n');
    
    const startTime = Date.now();
    
    try {
      // Run tests in optimal order
      await this.runUnitTests();
      await this.runIntegrationTests();
      await this.runSecurityTests();
      await this.runPerformanceTests();
      await this.runE2ETests();
      
      // Generate comprehensive reports
      await this.generateReports();
      
      const duration = Date.now() - startTime;
      this.testResults.summary = {
        totalDuration: duration,
        status: 'completed',
        overallResult: this.calculateOverallResult()
      };
      
      console.log(`\n✅ Test suite completed in ${(duration / 1000).toFixed(2)}s`);
      console.log(`📊 Overall Result: ${this.testResults.summary.overallResult}\n`);
      
      this.printTestSummary();
      
      // Exit with appropriate code
      const success = this.testResults.summary.overallResult === 'PASS';
      process.exit(success ? 0 : 1);
      
    } catch (error) {
      console.error('❌ Test suite failed:', error.message);
      this.testResults.summary = {
        totalDuration: Date.now() - startTime,
        status: 'failed',
        error: error.message,
        overallResult: 'FAIL'
      };
      
      await this.generateReports();
      process.exit(1);
    }
  }

  async runUnitTests() {
    console.log('🧪 Running unit tests...');
    
    try {
      const output = execSync('npm run test:unit --silent', {
        encoding: 'utf8',
        timeout: 300000,
        cwd: path.join(__dirname, '..')
      });
      
      this.testResults.unit = {
        status: 'passed',
        output: output,
        duration: this.extractDuration(output),
        coverage: this.extractCoverage(output)
      };
      
      console.log('✅ Unit tests passed');
      
    } catch (error) {
      console.log('❌ Unit tests failed');
      this.testResults.unit = {
        status: 'failed',
        error: error.message,
        output: error.stdout || '',
        duration: 0
      };
    }
  }

  async runIntegrationTests() {
    console.log('🔗 Running integration tests...');
    
    try {
      const output = execSync('npm run test:integration --silent', {
        encoding: 'utf8',
        timeout: 600000,
        cwd: path.join(__dirname, '..')
      });
      
      this.testResults.integration = {
        status: 'passed',
        output: output,
        duration: this.extractDuration(output)
      };
      
      console.log('✅ Integration tests passed');
      
    } catch (error) {
      console.log('❌ Integration tests failed');
      this.testResults.integration = {
        status: 'failed',
        error: error.message,
        output: error.stdout || '',
        duration: 0
      };
    }
  }

  async runSecurityTests() {
    console.log('🔒 Running security tests...');
    
    try {
      // Run security test suites
      const authResults = await this.runCommand('npm test -- tests/security/auth-security.test.ts');
      const xssResults = await this.runCommand('npm test -- tests/security/xss-prevention.test.ts');
      
      // Generate security report
      const SecurityReportGenerator = require('./generate-security-report.js');
      const securityGenerator = new SecurityReportGenerator();
      const securityReport = await securityGenerator.generateReport();
      
      this.testResults.security = {
        status: 'completed',
        authTests: this.parseTestOutput(authResults),
        xssTests: this.parseTestOutput(xssResults),
        report: securityReport,
        overallScore: securityReport.summary?.overallSecurityScore || 0
      };
      
      console.log(`✅ Security tests completed (Score: ${this.testResults.security.overallScore}%)`);
      
    } catch (error) {
      console.log('❌ Security tests failed');
      this.testResults.security = {
        status: 'failed',
        error: error.message,
        overallScore: 0
      };
    }
  }

  async runPerformanceTests() {
    console.log('⚡ Running performance tests...');
    
    try {
      // Generate performance report (includes running all performance tests)
      const PerformanceReportGenerator = require('./generate-performance-report.js');
      const performanceGenerator = new PerformanceReportGenerator();
      const performanceReport = await performanceGenerator.generateReport();
      
      this.testResults.performance = {
        status: 'completed',
        report: performanceReport,
        loadTests: performanceReport.loadTests,
        stressTests: performanceReport.stressTests,
        apiTests: performanceReport.apiTests,
        websocketTests: performanceReport.websocketTests,
        overallGrade: performanceGenerator.calculateOverallGrade(performanceReport)
      };
      
      console.log(`✅ Performance tests completed (Grade: ${this.testResults.performance.overallGrade})`);
      
    } catch (error) {
      console.log('❌ Performance tests failed');
      this.testResults.performance = {
        status: 'failed',
        error: error.message,
        overallGrade: 'F'
      };
    }
  }

  async runE2ETests() {
    console.log('🎭 Running E2E tests...');
    
    try {
      const output = execSync('npm run test:e2e --silent', {
        encoding: 'utf8',
        timeout: 900000, // 15 minutes
        cwd: path.join(__dirname, '..')
      });
      
      this.testResults.e2e = {
        status: 'passed',
        output: output,
        duration: this.extractDuration(output),
        scenarios: this.extractE2EScenarios(output)
      };
      
      console.log('✅ E2E tests passed');
      
    } catch (error) {
      console.log('❌ E2E tests failed');
      this.testResults.e2e = {
        status: 'failed',
        error: error.message,
        output: error.stdout || '',
        duration: 0
      };
    }
  }

  async runCommand(command) {
    return new Promise((resolve, reject) => {
      try {
        const output = execSync(command, {
          encoding: 'utf8',
          timeout: 300000,
          cwd: path.join(__dirname, '..')
        });
        resolve(output);
      } catch (error) {
        reject(error);
      }
    });
  }

  parseTestOutput(output) {
    // Simple test output parser
    const lines = output.split('\n');
    const summary = {
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0
    };
    
    lines.forEach(line => {
      if (line.includes('passing')) {
        const match = line.match(/(\d+) passing/);
        if (match) summary.passed = parseInt(match[1]);
      }
      if (line.includes('failing')) {
        const match = line.match(/(\d+) failing/);
        if (match) summary.failed = parseInt(match[1]);
      }
      if (line.includes('pending')) {
        const match = line.match(/(\d+) pending/);
        if (match) summary.skipped = parseInt(match[1]);
      }
    });
    
    summary.total = summary.passed + summary.failed + summary.skipped;
    return summary;
  }

  extractDuration(output) {
    const match = output.match(/(\d+(?:\.\d+)?)(ms|s)/);
    if (match) {
      const value = parseFloat(match[1]);
      const unit = match[2];
      return unit === 's' ? value * 1000 : value;
    }
    return 0;
  }

  extractCoverage(output) {
    const lines = output.split('\n');
    const coverageLine = lines.find(line => line.includes('All files') && line.includes('%'));
    if (coverageLine) {
      const match = coverageLine.match(/(\d+(?:\.\d+)?)%/);
      return match ? parseFloat(match[1]) : 0;
    }
    return 0;
  }

  extractE2EScenarios(output) {
    const lines = output.split('\n');
    const scenarios = [];
    
    lines.forEach(line => {
      if (line.includes('✓') || line.includes('✗')) {
        scenarios.push({
          name: line.trim(),
          status: line.includes('✓') ? 'passed' : 'failed'
        });
      }
    });
    
    return scenarios;
  }

  calculateOverallResult() {
    const results = [
      this.testResults.unit?.status === 'passed',
      this.testResults.integration?.status === 'passed',
      this.testResults.security?.status === 'completed' && this.testResults.security?.overallScore >= 70,
      this.testResults.performance?.status === 'completed' && this.testResults.performance?.overallGrade !== 'F',
      this.testResults.e2e?.status === 'passed'
    ];
    
    const passCount = results.filter(Boolean).length;
    const totalCount = results.length;
    
    if (passCount === totalCount) return 'PASS';
    if (passCount >= totalCount * 0.8) return 'CONDITIONAL_PASS';
    return 'FAIL';
  }

  async generateReports() {
    console.log('📋 Generating comprehensive test reports...');
    
    // Generate JSON report
    const jsonReport = JSON.stringify(this.testResults, null, 2);
    fs.writeFileSync(path.join(this.reportDir, `comprehensive-test-report-${this.timestamp}.json`), jsonReport);
    
    // Generate HTML report
    const htmlReport = this.generateHTMLReport();
    fs.writeFileSync(path.join(this.reportDir, `comprehensive-test-report-${this.timestamp}.html`), htmlReport);
    
    // Generate CI/CD report
    const ciReport = this.generateCIReport();
    fs.writeFileSync(path.join(this.reportDir, 'ci-test-results.json'), JSON.stringify(ciReport, null, 2));
    
    // Generate summary for quick review
    const summary = this.generateExecutiveSummary();
    fs.writeFileSync(path.join(this.reportDir, 'test-executive-summary.md'), summary);
    
    console.log(`📊 Reports generated in ${this.reportDir}`);
  }

  generateHTMLReport() {
    const overallColor = this.testResults.summary.overallResult === 'PASS' ? '#28a745' : 
                        this.testResults.summary.overallResult === 'CONDITIONAL_PASS' ? '#ffc107' : '#dc3545';
    
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TableForge Comprehensive Test Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; }
        .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .overall-result { font-size: 48px; font-weight: bold; color: ${overallColor}; margin: 20px 0; }
        .test-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .test-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 6px solid #667eea; }
        .status-pass { color: #28a745; font-weight: bold; }
        .status-fail { color: #dc3545; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .metric { display: flex; justify-content: space-between; margin: 10px 0; }
        .duration { color: #6c757d; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TableForge Comprehensive Test Report</h1>
            <p>Generated on ${new Date(this.testResults.timestamp).toLocaleString()}</p>
            <div class="overall-result">${this.testResults.summary.overallResult}</div>
            <p>Total Duration: ${((this.testResults.summary.totalDuration || 0) / 1000).toFixed(2)}s</p>
        </div>

        <div class="section">
            <h2>Test Suite Overview</h2>
            <div class="test-grid">
                <div class="test-card">
                    <h4>Unit Tests</h4>
                    <div class="metric">
                        <span>Status:</span>
                        <span class="${this.testResults.unit?.status === 'passed' ? 'status-pass' : 'status-fail'}">${this.testResults.unit?.status || 'Not run'}</span>
                    </div>
                    <div class="metric">
                        <span>Coverage:</span>
                        <span>${this.testResults.unit?.coverage || 0}%</span>
                    </div>
                </div>
                
                <div class="test-card">
                    <h4>Integration Tests</h4>
                    <div class="metric">
                        <span>Status:</span>
                        <span class="${this.testResults.integration?.status === 'passed' ? 'status-pass' : 'status-fail'}">${this.testResults.integration?.status || 'Not run'}</span>
                    </div>
                </div>
                
                <div class="test-card">
                    <h4>Security Tests</h4>
                    <div class="metric">
                        <span>Status:</span>
                        <span class="${this.testResults.security?.status === 'completed' ? 'status-pass' : 'status-fail'}">${this.testResults.security?.status || 'Not run'}</span>
                    </div>
                    <div class="metric">
                        <span>Security Score:</span>
                        <span>${this.testResults.security?.overallScore || 0}%</span>
                    </div>
                </div>
                
                <div class="test-card">
                    <h4>Performance Tests</h4>
                    <div class="metric">
                        <span>Status:</span>
                        <span class="${this.testResults.performance?.status === 'completed' ? 'status-pass' : 'status-fail'}">${this.testResults.performance?.status || 'Not run'}</span>
                    </div>
                    <div class="metric">
                        <span>Grade:</span>
                        <span>${this.testResults.performance?.overallGrade || 'N/A'}</span>
                    </div>
                </div>
                
                <div class="test-card">
                    <h4>E2E Tests</h4>
                    <div class="metric">
                        <span>Status:</span>
                        <span class="${this.testResults.e2e?.status === 'passed' ? 'status-pass' : 'status-fail'}">${this.testResults.e2e?.status || 'Not run'}</span>
                    </div>
                    <div class="metric">
                        <span>Scenarios:</span>
                        <span>${this.testResults.e2e?.scenarios?.length || 0}</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Detailed Results</h2>
            
            ${this.testResults.performance?.status === 'completed' ? `
            <h3>Performance Highlights</h3>
            <table>
                <tr><td>Load Test Error Rate</td><td>${((this.testResults.performance.report?.loadTests?.summary?.errorRate || 0) * 100).toFixed(2)}%</td></tr>
                <tr><td>P95 Response Time</td><td>${(this.testResults.performance.report?.loadTests?.summary?.p95ResponseTime || 0).toFixed(0)}ms</td></tr>
                <tr><td>Max Concurrent Users</td><td>${this.testResults.performance.report?.stressTests?.summary?.peakUsers || 0}</td></tr>
                <tr><td>API Throughput</td><td>${(this.testResults.performance.report?.apiTests?.summary?.overallThroughput || 0).toFixed(1)} req/s</td></tr>
            </table>
            ` : ''}
            
            ${this.testResults.security?.status === 'completed' ? `
            <h3>Security Highlights</h3>
            <table>
                <tr><td>Authentication Tests</td><td class="${this.testResults.security.authTests?.failed === 0 ? 'status-pass' : 'status-fail'}">${this.testResults.security.authTests?.passed || 0}/${this.testResults.security.authTests?.total || 0} Passed</td></tr>
                <tr><td>XSS Prevention Tests</td><td class="${this.testResults.security.xssTests?.failed === 0 ? 'status-pass' : 'status-fail'}">${this.testResults.security.xssTests?.passed || 0}/${this.testResults.security.xssTests?.total || 0} Passed</td></tr>
                <tr><td>Overall Security Score</td><td>${this.testResults.security.overallScore}%</td></tr>
            </table>
            ` : ''}
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            ${this.generateRecommendationsList()}
        </div>
    </div>
</body>
</html>`;
  }

  generateCIReport() {
    return {
      status: this.testResults.summary.overallResult,
      timestamp: this.testResults.timestamp,
      duration: this.testResults.summary.totalDuration,
      tests: {
        unit: { status: this.testResults.unit?.status, coverage: this.testResults.unit?.coverage },
        integration: { status: this.testResults.integration?.status },
        security: { status: this.testResults.security?.status, score: this.testResults.security?.overallScore },
        performance: { status: this.testResults.performance?.status, grade: this.testResults.performance?.overallGrade },
        e2e: { status: this.testResults.e2e?.status }
      },
      quality_gates: {
        unit_tests_pass: this.testResults.unit?.status === 'passed',
        security_score_above_70: (this.testResults.security?.overallScore || 0) >= 70,
        performance_grade_not_f: this.testResults.performance?.overallGrade !== 'F',
        e2e_tests_pass: this.testResults.e2e?.status === 'passed'
      }
    };
  }

  generateExecutiveSummary() {
    return `# TableForge Test Executive Summary

**Generated:** ${new Date(this.testResults.timestamp).toLocaleString()}
**Overall Result:** ${this.testResults.summary.overallResult}
**Duration:** ${((this.testResults.summary.totalDuration || 0) / 1000).toFixed(2)}s

## Test Results Summary

### ✅ **Unit Tests**
- Status: ${this.testResults.unit?.status || 'Not run'}
- Coverage: ${this.testResults.unit?.coverage || 0}%

### 🔗 **Integration Tests** 
- Status: ${this.testResults.integration?.status || 'Not run'}

### 🔒 **Security Tests**
- Status: ${this.testResults.security?.status || 'Not run'}
- Security Score: ${this.testResults.security?.overallScore || 0}%

### ⚡ **Performance Tests**
- Status: ${this.testResults.performance?.status || 'Not run'} 
- Grade: ${this.testResults.performance?.overallGrade || 'N/A'}

### 🎭 **E2E Tests**
- Status: ${this.testResults.e2e?.status || 'Not run'}
- Scenarios: ${this.testResults.e2e?.scenarios?.length || 0}

## Key Metrics

${this.testResults.performance?.status === 'completed' ? `
### Performance Metrics
- **Error Rate:** ${((this.testResults.performance.report?.loadTests?.summary?.errorRate || 0) * 100).toFixed(2)}%
- **P95 Response Time:** ${(this.testResults.performance.report?.loadTests?.summary?.p95ResponseTime || 0).toFixed(0)}ms
- **Max Concurrent Users:** ${this.testResults.performance.report?.stressTests?.summary?.peakUsers || 0}
- **API Throughput:** ${(this.testResults.performance.report?.apiTests?.summary?.overallThroughput || 0).toFixed(1)} req/s
` : ''}

${this.testResults.security?.status === 'completed' ? `
### Security Metrics
- **Overall Security Score:** ${this.testResults.security.overallScore}%
- **Critical Vulnerabilities:** ${this.testResults.security.report?.recommendations?.filter(r => r.severity === 'CRITICAL').length || 0}
- **High Priority Issues:** ${this.testResults.security.report?.recommendations?.filter(r => r.severity === 'HIGH').length || 0}
` : ''}

## Quality Gates Status

${this.generateQualityGatesStatus()}

---
*This report was automatically generated by the TableForge testing pipeline.*`;
  }

  generateQualityGatesStatus() {
    const gates = [
      { name: 'Unit Tests Pass', status: this.testResults.unit?.status === 'passed' },
      { name: 'Security Score ≥ 70%', status: (this.testResults.security?.overallScore || 0) >= 70 },
      { name: 'Performance Grade ≠ F', status: this.testResults.performance?.overallGrade !== 'F' },
      { name: 'E2E Tests Pass', status: this.testResults.e2e?.status === 'passed' }
    ];

    return gates.map(gate => 
      `- ${gate.status ? '✅' : '❌'} ${gate.name}`
    ).join('\n');
  }

  generateRecommendationsList() {
    const recommendations = [];
    
    if (this.testResults.unit?.status === 'failed') {
      recommendations.push('• Fix failing unit tests to ensure code quality');
    }
    
    if ((this.testResults.unit?.coverage || 0) < 80) {
      recommendations.push('• Increase unit test coverage above 80%');
    }
    
    if ((this.testResults.security?.overallScore || 0) < 70) {
      recommendations.push('• Address security vulnerabilities to improve security score');
    }
    
    if (this.testResults.performance?.overallGrade === 'F') {
      recommendations.push('• Optimize performance to improve grade');
    }
    
    if (this.testResults.e2e?.status === 'failed') {
      recommendations.push('• Fix E2E test failures for better user experience validation');
    }

    return recommendations.length > 0 ? 
      `<ul>${recommendations.map(rec => `<li>${rec.substring(2)}</li>`).join('')}</ul>` :
      '<p style="color: #28a745;">✅ No specific recommendations at this time. Great job!</p>';
  }

  printTestSummary() {
    console.log('📊 TEST SUMMARY');
    console.log('================');
    console.log(`Unit Tests:       ${this.getStatusEmoji(this.testResults.unit?.status === 'passed')} ${this.testResults.unit?.status || 'Not run'}`);
    console.log(`Integration:      ${this.getStatusEmoji(this.testResults.integration?.status === 'passed')} ${this.testResults.integration?.status || 'Not run'}`);
    console.log(`Security:         ${this.getStatusEmoji(this.testResults.security?.status === 'completed')} ${this.testResults.security?.status || 'Not run'} (${this.testResults.security?.overallScore || 0}%)`);
    console.log(`Performance:      ${this.getStatusEmoji(this.testResults.performance?.status === 'completed')} ${this.testResults.performance?.status || 'Not run'} (${this.testResults.performance?.overallGrade || 'N/A'})`);
    console.log(`E2E:              ${this.getStatusEmoji(this.testResults.e2e?.status === 'passed')} ${this.testResults.e2e?.status || 'Not run'}`);
    console.log('================');
    console.log(`Overall:          ${this.getStatusEmoji(this.testResults.summary.overallResult === 'PASS')} ${this.testResults.summary.overallResult}`);
    console.log(`\n📁 Reports available in: ${this.reportDir}`);
  }

  getStatusEmoji(passed) {
    return passed ? '✅' : '❌';
  }
}

// CLI execution with arguments
async function main() {
  const args = process.argv.slice(2);
  const runner = new TestRunner();
  
  if (args.includes('--help')) {
    console.log(`
TableForge Comprehensive Test Runner

Usage: node run-tests.js [options]

Options:
  --help              Show this help message
  --unit-only         Run only unit tests
  --security-only     Run only security tests  
  --performance-only  Run only performance tests
  --e2e-only          Run only E2E tests
  --skip-reports      Skip report generation

Examples:
  node run-tests.js                    # Run all tests
  node run-tests.js --unit-only        # Run only unit tests
  node run-tests.js --security-only    # Run only security tests
    `);
    process.exit(0);
  }

  if (args.includes('--unit-only')) {
    await runner.runUnitTests();
  } else if (args.includes('--security-only')) {
    await runner.runSecurityTests();
  } else if (args.includes('--performance-only')) {
    await runner.runPerformanceTests();
  } else if (args.includes('--e2e-only')) {
    await runner.runE2ETests();
  } else {
    await runner.runAllTests();
  }
}

if (require.main === module) {
  main().catch(error => {
    console.error('❌ Test runner failed:', error);
    process.exit(1);
  });
}

module.exports = TestRunner;
