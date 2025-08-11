/**
 * Color contrast analysis and accessibility compliance hook
 * Ensures WCAG compliance for color combinations in light/dark modes
 */

import { useState, useCallback, useEffect } from 'react';

interface ContrastResult {
  ratio: number;
  level: 'AA' | 'AAA' | 'fail';
  isLargeText: boolean;
  passes: boolean;
}

interface ColorPalette {
  name: string;
  colors: {
    background: string;
    foreground: string;
    muted: string;
    mutedForeground: string;
    border: string;
    primary: string;
    primaryForeground: string;
    secondary: string;
    secondaryForeground: string;
    destructive: string;
    destructiveForeground: string;
    warning: string;
    warningForeground: string;
    success: string;
    successForeground: string;
  };
}

interface ColorContrastReport {
  palette: string;
  mode: 'light' | 'dark';
  results: Array<{
    combination: string;
    foreground: string;
    background: string;
    contrast: ContrastResult;
    recommendations?: string[];
  }>;
  overallScore: number;
  compliance: 'AAA' | 'AA' | 'partial' | 'fail';
}

export function useColorContrast() {
  const [contrastReports, setContrastReports] = useState<ColorContrastReport[]>([]);
  const [currentMode, setCurrentMode] = useState<'light' | 'dark'>('light');

  // Convert hex to RGB
  const hexToRgb = useCallback((hex: string): [number, number, number] | null => {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result 
      ? [
          parseInt(result[1], 16),
          parseInt(result[2], 16),
          parseInt(result[3], 16),
        ]
      : null;
  }, []);

  // Calculate relative luminance
  const getLuminance = useCallback((r: number, g: number, b: number): number => {
    const rsRGB = r / 255;
    const gsRGB = g / 255;
    const bsRGB = b / 255;

    const rLum = rsRGB <= 0.03928 ? rsRGB / 12.92 : Math.pow((rsRGB + 0.055) / 1.055, 2.4);
    const gLum = gsRGB <= 0.03928 ? gsRGB / 12.92 : Math.pow((gsRGB + 0.055) / 1.055, 2.4);
    const bLum = bsRGB <= 0.03928 ? bsRGB / 12.92 : Math.pow((bsRGB + 0.055) / 1.055, 2.4);

    return 0.2126 * rLum + 0.7152 * gLum + 0.0722 * bLum;
  }, []);

  // Calculate contrast ratio
  const getContrastRatio = useCallback((color1: string, color2: string): number => {
    const rgb1 = hexToRgb(color1);
    const rgb2 = hexToRgb(color2);

    if (!rgb1 || !rgb2) return 1;

    const lum1 = getLuminance(...rgb1);
    const lum2 = getLuminance(...rgb2);

    const brightest = Math.max(lum1, lum2);
    const darkest = Math.min(lum1, lum2);

    return (brightest + 0.05) / (darkest + 0.05);
  }, [hexToRgb, getLuminance]);

  // Evaluate contrast ratio against WCAG standards
  const evaluateContrast = useCallback((
    ratio: number, 
    isLargeText: boolean = false
  ): ContrastResult => {
    const aaThreshold = isLargeText ? 3.0 : 4.5;
    const aaaThreshold = isLargeText ? 4.5 : 7.0;

    let level: 'AA' | 'AAA' | 'fail' = 'fail';
    if (ratio >= aaaThreshold) level = 'AAA';
    else if (ratio >= aaThreshold) level = 'AA';

    return {
      ratio,
      level,
      isLargeText,
      passes: ratio >= aaThreshold,
    };
  }, []);

  // Get CSS custom property value
  const getCSSCustomProperty = useCallback((property: string): string => {
    const value = getComputedStyle(document.documentElement)
      .getPropertyValue(property)
      .trim();
    
    // Convert HSL to hex if needed
    if (value.startsWith('hsl(')) {
      return hslToHex(value);
    }
    
    return value.startsWith('#') ? value : `#${value}`;
  }, []);

  // Convert HSL to hex (simplified)
  const hslToHex = useCallback((hslString: string): string => {
    const hslMatch = hslString.match(/hsl\((\d+),\s*(\d+)%,\s*(\d+)%\)/);
    if (!hslMatch) return '#000000';

    const h = parseInt(hslMatch[1]) / 360;
    const s = parseInt(hslMatch[2]) / 100;
    const l = parseInt(hslMatch[3]) / 100;

    const hueToRgb = (p: number, q: number, t: number) => {
      if (t < 0) t += 1;
      if (t > 1) t -= 1;
      if (t < 1/6) return p + (q - p) * 6 * t;
      if (t < 1/2) return q;
      if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
      return p;
    };

    let r, g, b;
    if (s === 0) {
      r = g = b = l;
    } else {
      const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
      const p = 2 * l - q;
      r = hueToRgb(p, q, h + 1/3);
      g = hueToRgb(p, q, h);
      b = hueToRgb(p, q, h - 1/3);
    }

    const toHex = (c: number) => {
      const hex = Math.round(c * 255).toString(16);
      return hex.length === 1 ? '0' + hex : hex;
    };

    return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
  }, []);

  // Analyze color palette for contrast compliance
  const analyzePalette = useCallback((palette: ColorPalette, mode: 'light' | 'dark'): ColorContrastReport => {
    const results = [];
    const { colors } = palette;

    // Critical color combinations to test
    const combinations = [
      { name: 'Body Text', fg: colors.foreground, bg: colors.background },
      { name: 'Muted Text', fg: colors.mutedForeground, bg: colors.background },
      { name: 'Primary Button', fg: colors.primaryForeground, bg: colors.primary },
      { name: 'Secondary Button', fg: colors.secondaryForeground, bg: colors.secondary },
      { name: 'Destructive Button', fg: colors.destructiveForeground, bg: colors.destructive },
      { name: 'Warning Text', fg: colors.warningForeground, bg: colors.warning },
      { name: 'Success Text', fg: colors.successForeground, bg: colors.success },
      { name: 'Border on Background', fg: colors.border, bg: colors.background },
      { name: 'Primary on Background', fg: colors.primary, bg: colors.background },
      { name: 'Muted Text on Muted', fg: colors.mutedForeground, bg: colors.muted },
    ];

    for (const combo of combinations) {
      const ratio = getContrastRatio(combo.fg, combo.bg);
      const contrast = evaluateContrast(ratio);
      const recommendations = [];

      if (!contrast.passes) {
        if (ratio < 3.0) {
          recommendations.push('Consider using a completely different color');
          recommendations.push('Increase saturation or lightness difference');
        } else {
          recommendations.push('Slightly adjust lightness for better contrast');
          recommendations.push('Consider adding a subtle border or shadow');
        }
      }

      results.push({
        combination: combo.name,
        foreground: combo.fg,
        background: combo.bg,
        contrast,
        recommendations: recommendations.length > 0 ? recommendations : undefined,
      });
    }

    // Calculate overall score
    const passingResults = results.filter(r => r.contrast.passes);
    const aaaResults = results.filter(r => r.contrast.level === 'AAA');
    const overallScore = Math.round((passingResults.length / results.length) * 100);

    // Determine compliance level
    let compliance: ColorContrastReport['compliance'];
    if (aaaResults.length === results.length) compliance = 'AAA';
    else if (passingResults.length === results.length) compliance = 'AA';
    else if (passingResults.length > results.length * 0.8) compliance = 'partial';
    else compliance = 'fail';

    return {
      palette: palette.name,
      mode,
      results,
      overallScore,
      compliance,
    };
  }, [getContrastRatio, evaluateContrast]);

  // Get current theme colors from CSS custom properties
  const getCurrentThemeColors = useCallback((): ColorPalette => {
    return {
      name: 'Current Theme',
      colors: {
        background: getCSSCustomProperty('--background'),
        foreground: getCSSCustomProperty('--foreground'),
        muted: getCSSCustomProperty('--muted'),
        mutedForeground: getCSSCustomProperty('--muted-foreground'),
        border: getCSSCustomProperty('--border'),
        primary: getCSSCustomProperty('--primary'),
        primaryForeground: getCSSCustomProperty('--primary-foreground'),
        secondary: getCSSCustomProperty('--secondary'),
        secondaryForeground: getCSSCustomProperty('--secondary-foreground'),
        destructive: getCSSCustomProperty('--destructive'),
        destructiveForeground: getCSSCustomProperty('--destructive-foreground'),
        warning: getCSSCustomProperty('--warning') || '#f59e0b',
        warningForeground: getCSSCustomProperty('--warning-foreground') || '#ffffff',
        success: getCSSCustomProperty('--success') || '#10b981',
        successForeground: getCSSCustomProperty('--success-foreground') || '#ffffff',
      },
    };
  }, [getCSSCustomProperty]);

  // Run contrast analysis
  const runContrastAnalysis = useCallback(() => {
    const currentPalette = getCurrentThemeColors();
    const report = analyzePalette(currentPalette, currentMode);
    setContrastReports([report]);
  }, [getCurrentThemeColors, analyzePalette, currentMode]);

  // Generate contrast improvement suggestions
  const generateImprovements = useCallback((report: ColorContrastReport) => {
    const suggestions: string[] = [];
    const failingResults = report.results.filter(r => !r.contrast.passes);

    if (failingResults.length === 0) {
      suggestions.push('All color combinations meet WCAG AA standards!');
      return suggestions;
    }

    suggestions.push(`${failingResults.length} color combinations need improvement:`);

    failingResults.forEach(result => {
      suggestions.push(`• ${result.combination}: ${result.contrast.ratio.toFixed(2)}:1 (needs ${result.contrast.isLargeText ? '3.0' : '4.5'}:1)`);
    });

    suggestions.push('');
    suggestions.push('General improvements:');
    if (report.mode === 'dark') {
      suggestions.push('• Use lighter text colors on dark backgrounds');
      suggestions.push('• Ensure sufficient contrast for borders and dividers');
    } else {
      suggestions.push('• Use darker text colors on light backgrounds');
      suggestions.push('• Consider using pure white (#ffffff) backgrounds');
    }

    return suggestions;
  }, []);

  // Detect current theme mode
  useEffect(() => {
    const detectThemeMode = () => {
      const isDark = document.documentElement.classList.contains('dark') ||
                    window.matchMedia('(prefers-color-scheme: dark)').matches;
      setCurrentMode(isDark ? 'dark' : 'light');
    };

    detectThemeMode();

    // Watch for theme changes
    const observer = new MutationObserver(detectThemeMode);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    });

    // Watch for system theme changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    mediaQuery.addEventListener('change', detectThemeMode);

    return () => {
      observer.disconnect();
      mediaQuery.removeEventListener('change', detectThemeMode);
    };
  }, []);

  // Run analysis when mode changes
  useEffect(() => {
    runContrastAnalysis();
  }, [currentMode, runContrastAnalysis]);

  return {
    contrastReports,
    currentMode,
    runContrastAnalysis,
    generateImprovements,
    getContrastRatio,
    evaluateContrast,
  };
}