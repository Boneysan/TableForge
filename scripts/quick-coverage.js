#!/usr/bin/env node

/**
 * Quick coverage assessment script
 * Runs unit tests with coverage and extracts key metrics
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🧪 Running Quick Coverage Assessment...\n');

try {
  // Run tests with coverage (timeout after 60 seconds)
  console.log('📊 Executing unit tests with coverage...');
  
  const coverageCommand = 'npx vitest run tests/unit --coverage --reporter=verbose';
  const result = execSync(coverageCommand, { 
    encoding: 'utf8', 
    timeout: 60000,
    stdio: 'pipe'
  });
  
  console.log('\n📈 Coverage Results:');
  
  // Extract coverage summary from output
  const lines = result.split('\n');
  let inCoverageSummary = false;
  
  for (const line of lines) {
    if (line.includes('Coverage report') || line.includes('% Coverage report')) {
      inCoverageSummary = true;
      continue;
    }
    
    if (inCoverageSummary && (line.includes('%') || line.includes('Files') || line.includes('Lines'))) {
      console.log(line);
    }
    
    if (line.includes('Test Files') || line.includes('Tests')) {
      console.log('\n🎯 Test Summary:');
      console.log(line);
    }
  }
  
  // Check for coverage files
  const coverageDir = path.join(process.cwd(), 'coverage');
  if (fs.existsSync(coverageDir)) {
    console.log('\n📁 Coverage files generated in:', coverageDir);
    const files = fs.readdirSync(coverageDir);
    console.log('   Files:', files.join(', '));
  }
  
  console.log('\n✅ Coverage assessment complete!');
  
} catch (error) {
  console.error('❌ Coverage assessment failed:', error.message);
  
  // If coverage fails, just run basic test count
  try {
    console.log('\n🔄 Falling back to basic test count...');
    const basicResult = execSync('npx vitest run tests/unit --reporter=verbose', { 
      encoding: 'utf8',
      timeout: 30000 
    });
    
    const lines = basicResult.split('\n');
    for (const line of lines) {
      if (line.includes('Test Files') || line.includes('Tests')) {
        console.log(line);
      }
    }
    
  } catch (basicError) {
    console.error('❌ Basic test run also failed:', basicError.message);
  }
}
