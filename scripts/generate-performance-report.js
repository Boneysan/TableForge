#!/usr/bin/env node

/**
 * Performance Report Generator - Phase 2 Week 4
 * Automated generation of comprehensive performance test reports
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class PerformanceReportGenerator {
  constructor() {
    this.reportDir = path.join(__dirname, '../reports');
    this.timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    this.reportPath = path.join(this.reportDir, `performance-report-${this.timestamp}.html`);
    
    this.ensureReportDirectory();
  }

  ensureReportDirectory() {
    if (!fs.existsSync(this.reportDir)) {
      fs.mkdirSync(this.reportDir, { recursive: true });
    }
  }

  async generateReport() {
    console.log('Generating comprehensive performance report...');
    
    const reportData = {
      timestamp: new Date().toISOString(),
      summary: await this.generateSummary(),
      loadTests: await this.runLoadTests(),
      stressTests: await this.runStressTests(),
      apiTests: await this.runApiTests(),
      websocketTests: await this.runWebSocketTests(),
      benchmarks: await this.runBenchmarks(),
      recommendations: this.generateRecommendations()
    };

    const htmlReport = this.generateHTMLReport(reportData);
    const jsonReport = JSON.stringify(reportData, null, 2);
    
    // Write reports
    fs.writeFileSync(this.reportPath, htmlReport);
    fs.writeFileSync(this.reportPath.replace('.html', '.json'), jsonReport);
    
    // Generate summary files
    await this.generateSummaryFiles(reportData);
    
    console.log(`Performance report generated: ${this.reportPath}`);
    return reportData;
  }

  async generateSummary() {
    return {
      testStartTime: new Date().toISOString(),
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        memory: process.memoryUsage(),
        cpu: require('os').cpus().length,
        hostname: require('os').hostname()
      },
      testConfiguration: {
        baseUrl: process.env.BASE_URL || 'http://localhost:5000',
        wsUrl: process.env.WS_URL || 'ws://localhost:5000/ws',
        maxConcurrentUsers: 1000,
        testDuration: '15 minutes',
        browsers: ['Chrome', 'Firefox', 'Safari', 'Edge']
      }
    };
  }

  async runLoadTests() {
    console.log('Running load tests...');
    
    try {
      const output = execSync('k6 run --out json=load-test-results.json tests/performance/load/basic-load.js', {
        encoding: 'utf8',
        timeout: 600000, // 10 minutes
        cwd: path.join(__dirname, '..')
      });
      
      const resultsFile = path.join(__dirname, '../load-test-results.json');
      const results = this.parseK6Results(resultsFile);
      
      return {
        status: 'completed',
        duration: results.duration,
        metrics: results.metrics,
        thresholds: results.thresholds,
        summary: {
          totalRequests: results.metrics.http_reqs?.values?.count || 0,
          errorRate: results.metrics.http_req_failed?.values?.rate || 0,
          avgResponseTime: results.metrics.http_req_duration?.values?.avg || 0,
          p95ResponseTime: results.metrics.http_req_duration?.values?.['p(95)'] || 0,
          maxConcurrentUsers: results.metrics.vus_max?.values?.max || 0
        }
      };
    } catch (error) {
      console.error('Load test failed:', error.message);
      return {
        status: 'failed',
        error: error.message,
        summary: {
          totalRequests: 0,
          errorRate: 1,
          avgResponseTime: 0,
          p95ResponseTime: 0,
          maxConcurrentUsers: 0
        }
      };
    }
  }

  async runStressTests() {
    console.log('Running stress tests...');
    
    try {
      const output = execSync('k6 run --out json=stress-test-results.json tests/performance/stress/stress-test.js', {
        encoding: 'utf8',
        timeout: 900000, // 15 minutes
        cwd: path.join(__dirname, '..')
      });
      
      const resultsFile = path.join(__dirname, '../stress-test-results.json');
      const results = this.parseK6Results(resultsFile);
      
      return {
        status: 'completed',
        breakingPoint: results.metrics.system_breaking_point?.values?.value || 'Not reached',
        maxUsers: results.metrics.max_concurrent_users?.values?.max || 0,
        resourceExhaustion: results.metrics.resource_exhaustion?.values?.rate || 0,
        recoveryTime: results.metrics.recovery_time?.values?.avg || 0,
        summary: {
          peakUsers: results.metrics.vus_max?.values?.max || 0,
          errorRateAtPeak: results.metrics.stress_test_errors?.values?.rate || 0,
          systemStability: results.metrics.resource_exhaustion?.values?.rate < 0.1 ? 'Stable' : 'Unstable'
        }
      };
    } catch (error) {
      console.error('Stress test failed:', error.message);
      return {
        status: 'failed',
        error: error.message,
        summary: {
          peakUsers: 0,
          errorRateAtPeak: 1,
          systemStability: 'Unknown'
        }
      };
    }
  }

  async runApiTests() {
    console.log('Running API performance tests...');
    
    try {
      const output = execSync('k6 run --out json=api-test-results.json tests/performance/api/api-performance.js', {
        encoding: 'utf8',
        timeout: 600000,
        cwd: path.join(__dirname, '..')
      });
      
      const resultsFile = path.join(__dirname, '../api-test-results.json');
      const results = this.parseK6Results(resultsFile);
      
      return {
        status: 'completed',
        endpoints: {
          authentication: {
            avgLatency: results.metrics.auth_latency?.values?.avg || 0,
            p95Latency: results.metrics.auth_latency?.values?.['p(95)'] || 0,
            throughput: results.metrics.api_throughput?.values?.rate || 0
          },
          roomOperations: {
            avgLatency: results.metrics.room_operations_latency?.values?.avg || 0,
            p95Latency: results.metrics.room_operations_latency?.values?.['p(95)'] || 0
          },
          assetOperations: {
            avgLatency: results.metrics.asset_operations_latency?.values?.avg || 0,
            p95Latency: results.metrics.asset_operations_latency?.values?.['p(95)'] || 0
          }
        },
        cachePerformance: {
          hitRate: results.metrics.cache_hit_rate?.values?.rate || 0
        },
        summary: {
          overallThroughput: results.metrics.http_reqs?.values?.rate || 0,
          avgApiResponseTime: results.metrics.api_response_time?.values?.avg || 0,
          apiErrorRate: results.metrics.api_error_rate?.values?.rate || 0
        }
      };
    } catch (error) {
      console.error('API test failed:', error.message);
      return {
        status: 'failed',
        error: error.message,
        summary: {
          overallThroughput: 0,
          avgApiResponseTime: 0,
          apiErrorRate: 1
        }
      };
    }
  }

  async runWebSocketTests() {
    console.log('Running WebSocket performance tests...');
    
    try {
      const output = execSync('k6 run --out json=ws-test-results.json tests/performance/load/websocket-load.js', {
        encoding: 'utf8',
        timeout: 600000,
        cwd: path.join(__dirname, '..')
      });
      
      const resultsFile = path.join(__dirname, '../ws-test-results.json');
      const results = this.parseK6Results(resultsFile);
      
      return {
        status: 'completed',
        connections: {
          maxConcurrent: results.metrics.ws_active_connections?.values?.max || 0,
          avgConnectionTime: results.metrics.ws_connection_time?.values?.avg || 0,
          connectionErrorRate: results.metrics.ws_connection_errors?.values?.rate || 0
        },
        messaging: {
          avgLatency: results.metrics.ws_message_latency?.values?.avg || 0,
          p95Latency: results.metrics.ws_message_latency?.values?.['p(95)'] || 0,
          messagesSent: results.metrics.ws_messages_sent?.values?.count || 0,
          messagesReceived: results.metrics.ws_messages_received?.values?.count || 0,
          messageErrorRate: results.metrics.ws_message_errors?.values?.rate || 0
        },
        reliability: {
          reconnectionRate: results.metrics.ws_reconnections?.values?.rate || 0
        }
      };
    } catch (error) {
      console.error('WebSocket test failed:', error.message);
      return {
        status: 'failed',
        error: error.message,
        connections: { maxConcurrent: 0, avgConnectionTime: 0, connectionErrorRate: 1 },
        messaging: { avgLatency: 0, p95Latency: 0, messagesSent: 0, messagesReceived: 0, messageErrorRate: 1 },
        reliability: { reconnectionRate: 0 }
      };
    }
  }

  async runBenchmarks() {
    console.log('Running API benchmarks...');
    
    const benchmarks = {};
    const endpoints = [
      { name: 'room_creation', url: '/api/rooms', method: 'POST', data: '{"name":"Benchmark Room"}' },
      { name: 'room_list', url: '/api/rooms', method: 'GET' },
      { name: 'asset_upload', url: '/api/rooms/test/assets', method: 'POST', data: '{"name":"test.png","type":"image/png"}' },
      { name: 'user_auth', url: '/api/auth/validate', method: 'GET' }
    ];

    for (const endpoint of endpoints) {
      try {
        const command = `autocannon -c 10 -d 30 -m ${endpoint.method} ${endpoint.data ? `-b '${endpoint.data}'` : ''} http://localhost:5000${endpoint.url}`;
        const output = execSync(command, { encoding: 'utf8', timeout: 45000 });
        
        benchmarks[endpoint.name] = this.parseAutocannonOutput(output);
      } catch (error) {
        console.error(`Benchmark failed for ${endpoint.name}:`, error.message);
        benchmarks[endpoint.name] = {
          latency: { average: 0, p99: 0 },
          requests: { average: 0, total: 0 },
          errors: { count: 1, rate: 1 }
        };
      }
    }

    return benchmarks;
  }

  parseK6Results(filePath) {
    try {
      if (!fs.existsSync(filePath)) {
        throw new Error(`Results file not found: ${filePath}`);
      }
      
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      
      return JSON.parse(lastLine);
    } catch (error) {
      console.error('Error parsing K6 results:', error.message);
      return { metrics: {}, thresholds: {} };
    }
  }

  parseAutocannonOutput(output) {
    const lines = output.split('\n');
    const stats = {
      latency: { average: 0, p99: 0 },
      requests: { average: 0, total: 0 },
      errors: { count: 0, rate: 0 }
    };

    try {
      lines.forEach(line => {
        if (line.includes('Latency')) {
          const match = line.match(/(\d+\.?\d*)\s*ms/);
          if (match) stats.latency.average = parseFloat(match[1]);
        }
        if (line.includes('99%')) {
          const match = line.match(/(\d+\.?\d*)\s*ms/);
          if (match) stats.latency.p99 = parseFloat(match[1]);
        }
        if (line.includes('Req/Sec')) {
          const match = line.match(/(\d+\.?\d*)/);
          if (match) stats.requests.average = parseFloat(match[1]);
        }
        if (line.includes('requests in')) {
          const match = line.match(/(\d+)\s*requests/);
          if (match) stats.requests.total = parseInt(match[1]);
        }
        if (line.includes('errors')) {
          const match = line.match(/(\d+)\s*errors/);
          if (match) stats.errors.count = parseInt(match[1]);
        }
      });

      if (stats.requests.total > 0) {
        stats.errors.rate = stats.errors.count / stats.requests.total;
      }
    } catch (error) {
      console.error('Error parsing autocannon output:', error);
    }

    return stats;
  }

  generateRecommendations(data) {
    const recommendations = [];

    // Analyze load test results
    if (data?.loadTests?.summary?.errorRate > 0.05) {
      recommendations.push({
        category: 'Reliability',
        priority: 'High',
        issue: 'High error rate under normal load',
        recommendation: 'Investigate error causes and improve error handling',
        impact: 'User experience degradation'
      });
    }

    if (data?.loadTests?.summary?.p95ResponseTime > 1000) {
      recommendations.push({
        category: 'Performance',
        priority: 'Medium',
        issue: 'Slow response times',
        recommendation: 'Optimize database queries and implement caching',
        impact: 'User experience and perceived performance'
      });
    }

    // Analyze stress test results
    if (data?.stressTests?.summary?.peakUsers < 500) {
      recommendations.push({
        category: 'Scalability',
        priority: 'High',
        issue: 'Low breaking point for concurrent users',
        recommendation: 'Implement horizontal scaling and load balancing',
        impact: 'System capacity and growth potential'
      });
    }

    // Analyze API performance
    if (data?.apiTests?.summary?.apiErrorRate > 0.02) {
      recommendations.push({
        category: 'API Reliability',
        priority: 'Medium',
        issue: 'API errors under load',
        recommendation: 'Review API error handling and add circuit breakers',
        impact: 'Integration reliability'
      });
    }

    // Analyze WebSocket performance
    if (data?.websocketTests?.messaging?.messageErrorRate > 0.01) {
      recommendations.push({
        category: 'Real-time Communication',
        priority: 'Medium',
        issue: 'WebSocket message errors',
        recommendation: 'Improve WebSocket error handling and reconnection logic',
        impact: 'Real-time features reliability'
      });
    }

    return recommendations;
  }

  generateHTMLReport(data) {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TableForge Performance Report - ${data.timestamp}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .metric-card { background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #667eea; }
        .metric-value { font-size: 24px; font-weight: bold; color: #667eea; }
        .metric-label { font-size: 14px; color: #666; margin-top: 5px; }
        .status-good { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-error { color: #dc3545; }
        .recommendations { background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; padding: 15px; }
        .recommendation { margin-bottom: 10px; padding: 10px; background: white; border-radius: 4px; }
        .priority-high { border-left: 4px solid #dc3545; }
        .priority-medium { border-left: 4px solid #ffc107; }
        .priority-low { border-left: 4px solid #28a745; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        .chart-placeholder { height: 200px; background: #f8f9fa; border-radius: 6px; display: flex; align-items: center; justify-content: center; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TableForge Performance Report</h1>
            <p>Generated on ${new Date(data.timestamp).toLocaleString()}</p>
            <p>Environment: ${data.summary?.environment?.platform} | Node.js ${data.summary?.environment?.nodeVersion}</p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value ${this.getStatusClass(data.loadTests?.summary?.errorRate, 0.05, true)}">${((data.loadTests?.summary?.errorRate || 0) * 100).toFixed(2)}%</div>
                    <div class="metric-label">Error Rate</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value ${this.getStatusClass(data.loadTests?.summary?.p95ResponseTime, 1000, false)}">${(data.loadTests?.summary?.p95ResponseTime || 0).toFixed(0)}ms</div>
                    <div class="metric-label">P95 Response Time</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${data.stressTests?.summary?.peakUsers || 0}</div>
                    <div class="metric-label">Peak Concurrent Users</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${(data.apiTests?.summary?.overallThroughput || 0).toFixed(1)}</div>
                    <div class="metric-label">Requests/Second</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Load Test Results</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">${data.loadTests?.summary?.totalRequests || 0}</div>
                    <div class="metric-label">Total Requests</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${(data.loadTests?.summary?.avgResponseTime || 0).toFixed(1)}ms</div>
                    <div class="metric-label">Avg Response Time</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${data.loadTests?.summary?.maxConcurrentUsers || 0}</div>
                    <div class="metric-label">Max Concurrent Users</div>
                </div>
            </div>
            <div class="chart-placeholder">Load Test Timeline Chart (Placeholder)</div>
        </div>

        <div class="section">
            <h2>Stress Test Results</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">${data.stressTests?.breakingPoint || 'Not reached'}</div>
                    <div class="metric-label">Breaking Point</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value ${this.getStatusClass(data.stressTests?.summary?.errorRateAtPeak, 0.5, true)}">${((data.stressTests?.summary?.errorRateAtPeak || 0) * 100).toFixed(1)}%</div>
                    <div class="metric-label">Error Rate at Peak</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${data.stressTests?.summary?.systemStability || 'Unknown'}</div>
                    <div class="metric-label">System Stability</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>API Performance</h2>
            <table>
                <thead>
                    <tr>
                        <th>Endpoint Category</th>
                        <th>Avg Latency (ms)</th>
                        <th>P95 Latency (ms)</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Authentication</td>
                        <td>${(data.apiTests?.endpoints?.authentication?.avgLatency || 0).toFixed(1)}</td>
                        <td>${(data.apiTests?.endpoints?.authentication?.p95Latency || 0).toFixed(1)}</td>
                        <td class="${this.getStatusClass(data.apiTests?.endpoints?.authentication?.p95Latency, 200, false)}">${this.getStatusText(data.apiTests?.endpoints?.authentication?.p95Latency, 200, false)}</td>
                    </tr>
                    <tr>
                        <td>Room Operations</td>
                        <td>${(data.apiTests?.endpoints?.roomOperations?.avgLatency || 0).toFixed(1)}</td>
                        <td>${(data.apiTests?.endpoints?.roomOperations?.p95Latency || 0).toFixed(1)}</td>
                        <td class="${this.getStatusClass(data.apiTests?.endpoints?.roomOperations?.p95Latency, 300, false)}">${this.getStatusText(data.apiTests?.endpoints?.roomOperations?.p95Latency, 300, false)}</td>
                    </tr>
                    <tr>
                        <td>Asset Operations</td>
                        <td>${(data.apiTests?.endpoints?.assetOperations?.avgLatency || 0).toFixed(1)}</td>
                        <td>${(data.apiTests?.endpoints?.assetOperations?.p95Latency || 0).toFixed(1)}</td>
                        <td class="${this.getStatusClass(data.apiTests?.endpoints?.assetOperations?.p95Latency, 1000, false)}">${this.getStatusText(data.apiTests?.endpoints?.assetOperations?.p95Latency, 1000, false)}</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>WebSocket Performance</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">${data.websocketTests?.connections?.maxConcurrent || 0}</div>
                    <div class="metric-label">Max Concurrent Connections</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${(data.websocketTests?.messaging?.avgLatency || 0).toFixed(1)}ms</div>
                    <div class="metric-label">Avg Message Latency</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${data.websocketTests?.messaging?.messagesSent || 0}</div>
                    <div class="metric-label">Messages Sent</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value ${this.getStatusClass(data.websocketTests?.messaging?.messageErrorRate, 0.01, true)}">${((data.websocketTests?.messaging?.messageErrorRate || 0) * 100).toFixed(2)}%</div>
                    <div class="metric-label">Message Error Rate</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <div class="recommendations">
                ${(data.recommendations || []).map(rec => `
                    <div class="recommendation priority-${rec.priority.toLowerCase()}">
                        <strong>${rec.category}</strong> - ${rec.priority} Priority
                        <br><strong>Issue:</strong> ${rec.issue}
                        <br><strong>Recommendation:</strong> ${rec.recommendation}
                        <br><strong>Impact:</strong> ${rec.impact}
                    </div>
                `).join('')}
            </div>
        </div>

        <div class="section">
            <h2>Test Configuration</h2>
            <table>
                <tr><td>Base URL</td><td>${data.summary?.testConfiguration?.baseUrl}</td></tr>
                <tr><td>WebSocket URL</td><td>${data.summary?.testConfiguration?.wsUrl}</td></tr>
                <tr><td>Max Concurrent Users</td><td>${data.summary?.testConfiguration?.maxConcurrentUsers}</td></tr>
                <tr><td>Test Duration</td><td>${data.summary?.testConfiguration?.testDuration}</td></tr>
                <tr><td>Platform</td><td>${data.summary?.environment?.platform}</td></tr>
                <tr><td>Node.js Version</td><td>${data.summary?.environment?.nodeVersion}</td></tr>
                <tr><td>CPU Cores</td><td>${data.summary?.environment?.cpu}</td></tr>
            </table>
        </div>
    </div>
</body>
</html>`;
  }

  getStatusClass(value, threshold, lowerIsBetter) {
    if (value === undefined || value === null) return 'status-warning';
    
    if (lowerIsBetter) {
      return value <= threshold ? 'status-good' : value <= threshold * 2 ? 'status-warning' : 'status-error';
    } else {
      return value >= threshold ? 'status-good' : value >= threshold * 0.5 ? 'status-warning' : 'status-error';
    }
  }

  getStatusText(value, threshold, lowerIsBetter) {
    if (value === undefined || value === null) return 'Unknown';
    
    if (lowerIsBetter) {
      return value <= threshold ? 'Good' : value <= threshold * 2 ? 'Warning' : 'Poor';
    } else {
      return value >= threshold ? 'Good' : value >= threshold * 0.5 ? 'Warning' : 'Poor';
    }
  }

  async generateSummaryFiles(data) {
    const summary = {
      timestamp: data.timestamp,
      overall_grade: this.calculateOverallGrade(data),
      key_metrics: {
        load_test_error_rate: data.loadTests?.summary?.errorRate || 0,
        p95_response_time: data.loadTests?.summary?.p95ResponseTime || 0,
        max_concurrent_users: data.stressTests?.summary?.peakUsers || 0,
        api_throughput: data.apiTests?.summary?.overallThroughput || 0,
        websocket_message_error_rate: data.websocketTests?.messaging?.messageErrorRate || 0
      },
      recommendations_count: data.recommendations?.length || 0,
      high_priority_issues: data.recommendations?.filter(r => r.priority === 'High').length || 0
    };

    // Write summary files
    fs.writeFileSync(path.join(this.reportDir, 'latest-summary.json'), JSON.stringify(summary, null, 2));
    fs.writeFileSync(path.join(this.reportDir, 'latest-report.html'), fs.readFileSync(this.reportPath));
    
    // Create metrics CSV for trend analysis
    const csvData = [
      'timestamp,error_rate,p95_response_time,max_users,throughput,ws_error_rate',
      `${data.timestamp},${summary.key_metrics.load_test_error_rate},${summary.key_metrics.p95_response_time},${summary.key_metrics.max_concurrent_users},${summary.key_metrics.api_throughput},${summary.key_metrics.websocket_message_error_rate}`
    ].join('\n');
    
    const csvPath = path.join(this.reportDir, 'performance-metrics.csv');
    if (fs.existsSync(csvPath)) {
      fs.appendFileSync(csvPath, '\n' + csvData.split('\n')[1]);
    } else {
      fs.writeFileSync(csvPath, csvData);
    }
  }

  calculateOverallGrade(data) {
    let score = 100;
    
    // Deduct points based on various metrics
    if ((data.loadTests?.summary?.errorRate || 0) > 0.05) score -= 20;
    if ((data.loadTests?.summary?.p95ResponseTime || 0) > 1000) score -= 15;
    if ((data.stressTests?.summary?.peakUsers || 0) < 500) score -= 15;
    if ((data.apiTests?.summary?.apiErrorRate || 0) > 0.02) score -= 10;
    if ((data.websocketTests?.messaging?.messageErrorRate || 0) > 0.01) score -= 10;
    
    // High priority recommendations reduce score
    const highPriorityCount = data.recommendations?.filter(r => r.priority === 'High').length || 0;
    score -= highPriorityCount * 5;
    
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }
}

// CLI execution
if (require.main === module) {
  const generator = new PerformanceReportGenerator();
  generator.generateReport()
    .then(data => {
      console.log('Performance report generation completed successfully');
      console.log(`Overall Grade: ${generator.calculateOverallGrade(data)}`);
      process.exit(0);
    })
    .catch(error => {
      console.error('Performance report generation failed:', error);
      process.exit(1);
    });
}

module.exports = PerformanceReportGenerator;
