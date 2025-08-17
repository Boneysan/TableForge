#!/usr/bin/env tsx
// scripts/run-performance-suite.ts
import { CachePerformanceTests } from '../tests/performance/cache-performance.test';
import { LoadScalingTests } from '../tests/performance/load-scaling.test';

async function runPerformanceSuite() {
  console.log('🚀 Starting comprehensive performance test suite...\n');
  
  try {
    // Run cache performance tests
    console.log('📊 Running cache performance tests...');
    const cacheTests = new CachePerformanceTests();
    const cacheResults = await cacheTests.runComprehensiveTestSuite();
    
    console.log('✅ Cache performance tests completed');
    console.log(`   Overall Success: ${cacheResults.overallSuccess}`);
    console.log(`   Performance Grade: ${cacheResults.performanceGrade}`);
    console.log(`   Duration: ${Math.round(cacheResults.totalDuration)}ms`);
    console.log(`   Hit Rate Improvement: ${cacheResults.summary.hitRateImprovement.toFixed(1)}%\n`);
    
    // Run load scaling tests
    console.log('📈 Running load scaling tests...');
    const loadTests = new LoadScalingTests();
    const loadResults = await loadTests.runComprehensiveLoadTestSuite();
    
    console.log('✅ Load scaling tests completed');
    console.log(`   Overall Success: ${loadResults.overallSuccess}`);
    console.log(`   Scaling Grade: ${loadResults.scalingCapability.scalingGrade}`);
    console.log(`   Max Recommended Load: ${loadResults.scalingCapability.maxRecommendedLoad}`);
    console.log(`   Linear Scaling: ${loadResults.scalingCapability.linearScaling ? 'Yes' : 'No'}\n`);
    
    // Overall summary
    const overallSuccess = cacheResults.overallSuccess && loadResults.overallSuccess;
    console.log('🎯 Performance Test Suite Summary');
    console.log('=================================');
    console.log(`Overall Status: ${overallSuccess ? '✅ PASSED' : '❌ FAILED'}`);
    console.log(`Cache Performance: ${cacheResults.performanceGrade}`);
    console.log(`Scaling Capability: ${loadResults.scalingCapability.scalingGrade}`);
    
    if (!overallSuccess) {
      console.log('\n⚠️  Issues Identified:');
      if (!cacheResults.overallSuccess) {
        console.log('   - Cache performance issues detected');
      }
      if (!loadResults.overallSuccess) {
        console.log('   - Load scaling issues detected');
      }
    }
    
    console.log('\n📋 Key Recommendations:');
    loadResults.recommendations.forEach(rec => console.log(`   • ${rec}`));
    
    process.exit(overallSuccess ? 0 : 1);
    
  } catch (error) {
    console.error('❌ Performance test suite failed:', error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runPerformanceSuite();
}
