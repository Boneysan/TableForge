// server/websocket/scaling/test-runner.ts
import { ScalingTestSuite } from './scaling-tests';
import { logger } from '../../utils/logger';

/**
 * Test Runner for WebSocket Scaling Tests
 * Provides CLI interface and automated test execution
 */
export class ScalingTestRunner {
  private testSuite: ScalingTestSuite;

  constructor() {
    this.testSuite = new ScalingTestSuite();
  }

  /**
   * Run specific test by name
   */
  async runTest(testName: string): Promise<void> {
    console.log(`\n🚀 Running WebSocket Scaling Test: ${testName}\n`);
    
    try {
      let result;
      
      switch (testName) {
        case 'basic':
          result = await this.testSuite.testBasicMultiInstanceCommunication();
          break;
        case 'load-balancing':
          result = await this.testSuite.testLoadBalancingEffectiveness();
          break;
        case 'failure-recovery':
          result = await this.testSuite.testInstanceFailureRecovery();
          break;
        case 'stress':
          result = await this.testSuite.testHighLoadStress();
          break;
        case 'monitoring':
          result = await this.testSuite.testMonitoringAndAlerting();
          break;
        default:
          throw new Error(`Unknown test: ${testName}`);
      }
      
      this.printTestResult(result);
      
    } catch (error) {
      console.error(`❌ Test failed: ${error}`);
      process.exit(1);
    }
  }

  /**
   * Run all tests
   */
  async runAllTests(): Promise<void> {
    console.log('\n🚀 Running Complete WebSocket Scaling Test Suite\n');
    console.log('=' .repeat(60));
    
    try {
      const suiteResult = await this.testSuite.runAllTests();
      this.printSuiteResult(suiteResult);
      
      if (!suiteResult.overallSuccess) {
        process.exit(1);
      }
      
    } catch (error) {
      console.error(`❌ Test suite failed: ${error}`);
      process.exit(1);
    }
  }

  /**
   * Run tests in CI/CD mode with JSON output
   */
  async runCI(): Promise<void> {
    try {
      const suiteResult = await this.testSuite.runAllTests();
      
      // Output JSON for CI/CD parsing
      console.log(JSON.stringify({
        success: suiteResult.overallSuccess,
        totalTests: suiteResult.totalTests,
        successfulTests: suiteResult.successfulTests,
        failedTests: suiteResult.failedTests,
        duration: suiteResult.totalDuration,
        results: suiteResult.results.map(r => ({
          testId: r.testId,
          success: r.success,
          duration: r.duration,
          error: r.error
        }))
      }, null, 2));
      
      if (!suiteResult.overallSuccess) {
        process.exit(1);
      }
      
    } catch (error) {
      console.error(JSON.stringify({ error: String(error) }));
      process.exit(1);
    }
  }

  /**
   * Run performance benchmark
   */
  async runBenchmark(): Promise<void> {
    console.log('\n📊 Running WebSocket Scaling Performance Benchmark\n');
    
    try {
      // Run stress test multiple times for consistent results
      const runs = 3;
      const results = [];
      
      for (let i = 0; i < runs; i++) {
        console.log(`Running benchmark ${i + 1}/${runs}...`);
        const result = await this.testSuite.testHighLoadStress();
        results.push(result);
        
        // Wait between runs
        await this.sleep(5000);
      }
      
      // Calculate averages
      const avgThroughput = results.reduce((sum, r) => sum + (r.metrics?.throughput || 0), 0) / runs;
      const avgLatency = results.reduce((sum, r) => sum + (r.metrics?.averageLatency || 0), 0) / runs;
      const avgErrorRate = results.reduce((sum, r) => sum + (r.metrics?.errorRate || 0), 0) / runs;
      
      console.log('\n📊 Benchmark Results:');
      console.log(`Average Throughput: ${avgThroughput.toFixed(2)} messages/second`);
      console.log(`Average Latency: ${avgLatency.toFixed(2)}ms`);
      console.log(`Average Error Rate: ${(avgErrorRate * 100).toFixed(2)}%`);
      
      // Performance thresholds
      const performanceGrade = this.calculatePerformanceGrade(avgThroughput, avgLatency, avgErrorRate);
      console.log(`Performance Grade: ${performanceGrade}`);
      
    } catch (error) {
      console.error(`❌ Benchmark failed: ${error}`);
      process.exit(1);
    }
  }

  private printTestResult(result: any): void {
    console.log(`Test: ${result.testId}`);
    console.log(`Status: ${result.success ? '✅ PASSED' : '❌ FAILED'}`);
    
    if (result.duration) {
      console.log(`Duration: ${result.duration}ms`);
    }
    
    if (result.metrics) {
      console.log('Metrics:');
      Object.entries(result.metrics).forEach(([key, value]) => {
        console.log(`  ${key}: ${value}`);
      });
    }
    
    if (result.error) {
      console.log(`Error: ${result.error}`);
    }
    
    console.log('');
  }

  private printSuiteResult(suiteResult: any): void {
    console.log('\n📋 Test Suite Results');
    console.log('=' .repeat(60));
    console.log(`Total Tests: ${suiteResult.totalTests}`);
    console.log(`Successful: ${suiteResult.successfulTests} ✅`);
    console.log(`Failed: ${suiteResult.failedTests} ❌`);
    console.log(`Success Rate: ${(suiteResult.successfulTests / suiteResult.totalTests * 100).toFixed(1)}%`);
    console.log(`Total Duration: ${suiteResult.totalDuration}ms`);
    console.log(`Overall Status: ${suiteResult.overallSuccess ? '✅ PASSED' : '❌ FAILED'}`);
    
    console.log('\n📊 Individual Test Results:');
    suiteResult.results.forEach((result: any) => {
      const status = result.success ? '✅' : '❌';
      const duration = result.duration ? ` (${result.duration}ms)` : '';
      console.log(`  ${status} ${result.testId}${duration}`);
      if (result.error) {
        console.log(`    Error: ${result.error}`);
      }
    });
    
    if (suiteResult.summary?.recommendations?.length > 0) {
      console.log('\n💡 Recommendations:');
      suiteResult.summary.recommendations.forEach((rec: string) => {
        console.log(`  • ${rec}`);
      });
    }
    
    console.log('\n' + '=' .repeat(60));
  }

  private calculatePerformanceGrade(throughput: number, latency: number, errorRate: number): string {
    let score = 0;
    
    // Throughput scoring (0-40 points)
    if (throughput >= 1000) score += 40;
    else if (throughput >= 500) score += 30;
    else if (throughput >= 100) score += 20;
    else if (throughput >= 50) score += 10;
    
    // Latency scoring (0-30 points)
    if (latency <= 50) score += 30;
    else if (latency <= 100) score += 25;
    else if (latency <= 200) score += 20;
    else if (latency <= 500) score += 10;
    
    // Error rate scoring (0-30 points)
    if (errorRate <= 0.01) score += 30;
    else if (errorRate <= 0.02) score += 25;
    else if (errorRate <= 0.05) score += 20;
    else if (errorRate <= 0.10) score += 10;
    
    if (score >= 90) return 'A+ (Excellent)';
    if (score >= 80) return 'A (Very Good)';
    if (score >= 70) return 'B (Good)';
    if (score >= 60) return 'C (Acceptable)';
    if (score >= 50) return 'D (Poor)';
    return 'F (Failing)';
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async cleanup(): Promise<void> {
    await this.testSuite.cleanup();
  }
}

// CLI Interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const command = args[0] || 'all';
  
  const runner = new ScalingTestRunner();
  
  const cleanup = async () => {
    console.log('\n🧹 Cleaning up test resources...');
    await runner.cleanup();
    process.exit(0);
  };
  
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  
  async function main() {
    try {
      switch (command) {
        case 'all':
          await runner.runAllTests();
          break;
        case 'ci':
          await runner.runCI();
          break;
        case 'benchmark':
          await runner.runBenchmark();
          break;
        case 'basic':
        case 'load-balancing':
        case 'failure-recovery':
        case 'stress':
        case 'monitoring':
          await runner.runTest(command);
          break;
        default:
          console.log('Usage: npm run test:scaling [all|ci|benchmark|basic|load-balancing|failure-recovery|stress|monitoring]');
          process.exit(1);
      }
    } catch (error) {
      console.error(`❌ Execution failed: ${error}`);
      process.exit(1);
    } finally {
      await cleanup();
    }
  }
  
  main();
}
