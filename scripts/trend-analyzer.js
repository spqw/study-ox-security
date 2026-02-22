#!/usr/bin/env node
/**
 * E10: Trend Analyzer
 *
 * Uses getIssuesTrendData to show how vulnerability counts change over time.
 * Generates text-based trend charts (ASCII sparklines and bar charts) per
 * severity, overall totals, and per-app breakdowns.
 *
 * Falls back to realistic mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/trend-analyzer.js [appFilter]
 *
 * Environment:
 *   OX_APP_NAME  — filter to a specific app name
 *   OX_DAYS      — number of days to analyze (default: 90)
 */
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

// ---------------------------------------------------------------------------
// API key detection
// ---------------------------------------------------------------------------
function loadEnvQuiet() {
  const envPath = resolve(process.cwd(), '.env');
  if (!existsSync(envPath)) return;
  const lines = readFileSync(envPath, 'utf-8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim();
    if (!process.env[key]) process.env[key] = val;
  }
}

loadEnvQuiet();
const USE_MOCK = !process.env.OX_API_KEY;

let queryFn;
if (!USE_MOCK) {
  const client = await import('../lib/ox-client.js');
  queryFn = client.query;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SEV_ICON = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Info: '⚪' };
const SPARK_CHARS = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

// ---------------------------------------------------------------------------
// Mock data — realistic iOS vulnerability trend data for offline development
// ---------------------------------------------------------------------------
function generateMockTrendData(days) {
  const data = [];
  const now = new Date();

  // Simulate realistic vulnerability trends for 3 iOS apps:
  //   - MyBankingApp-iOS: gradual improvement (critical/high going down)
  //   - HealthTracker-iOS: new app, rising issues as scanning ramps up, then stabilizing
  //   - ShopEasy-iOS: steady state with occasional spikes from dependency updates

  for (let d = days - 1; d >= 0; d--) {
    const date = new Date(now);
    date.setDate(date.getDate() - d);
    const dateStr = date.toISOString().slice(0, 10);
    const dayIndex = days - 1 - d;
    const progress = dayIndex / (days - 1); // 0 -> 1

    // MyBankingApp-iOS: improving security posture
    const bankNoise = () => Math.floor(Math.random() * 3) - 1;
    data.push({ date: dateStr, severity: 'Critical', count: Math.max(0, Math.round(8 - progress * 6) + bankNoise()), app: 'MyBankingApp-iOS' });
    data.push({ date: dateStr, severity: 'High', count: Math.max(0, Math.round(15 - progress * 9) + bankNoise()), app: 'MyBankingApp-iOS' });
    data.push({ date: dateStr, severity: 'Medium', count: Math.max(2, Math.round(22 - progress * 8) + bankNoise()), app: 'MyBankingApp-iOS' });
    data.push({ date: dateStr, severity: 'Low', count: Math.max(5, Math.round(30 - progress * 5) + bankNoise()), app: 'MyBankingApp-iOS' });

    // HealthTracker-iOS: ramp-up then stabilize (new app onboarded at day ~20)
    const htActive = dayIndex >= 15;
    const htRamp = htActive ? Math.min(1, (dayIndex - 15) / 30) : 0;
    const htStabilize = htActive && dayIndex > 45 ? Math.min(1, (dayIndex - 45) / 30) : 0;
    const htNoise = () => Math.floor(Math.random() * 2);
    if (htActive) {
      data.push({ date: dateStr, severity: 'Critical', count: Math.round(htRamp * 5 - htStabilize * 3) + htNoise(), app: 'HealthTracker-iOS' });
      data.push({ date: dateStr, severity: 'High', count: Math.round(htRamp * 12 - htStabilize * 5) + htNoise(), app: 'HealthTracker-iOS' });
      data.push({ date: dateStr, severity: 'Medium', count: Math.round(htRamp * 18 - htStabilize * 4) + htNoise(), app: 'HealthTracker-iOS' });
      data.push({ date: dateStr, severity: 'Low', count: Math.round(htRamp * 10 - htStabilize * 2) + htNoise(), app: 'HealthTracker-iOS' });
    }

    // ShopEasy-iOS: steady with dependency update spike around day 40-50
    const seSpike = (dayIndex >= 38 && dayIndex <= 52) ? 1 : 0;
    const sePostSpike = dayIndex > 52 ? Math.min(1, (dayIndex - 52) / 20) : 0;
    const seNoise = () => Math.floor(Math.random() * 2) - 1;
    data.push({ date: dateStr, severity: 'Critical', count: Math.max(0, 3 + seSpike * 4 - Math.round(sePostSpike * 5) + seNoise()), app: 'ShopEasy-iOS' });
    data.push({ date: dateStr, severity: 'High', count: Math.max(1, 8 + seSpike * 6 - Math.round(sePostSpike * 4) + seNoise()), app: 'ShopEasy-iOS' });
    data.push({ date: dateStr, severity: 'Medium', count: Math.max(3, 14 + seSpike * 3 - Math.round(sePostSpike * 2) + seNoise()), app: 'ShopEasy-iOS' });
    data.push({ date: dateStr, severity: 'Low', count: Math.max(5, 20 + seNoise()), app: 'ShopEasy-iOS' });
  }

  return data;
}

function getMockTrendData(days) {
  return {
    getIssuesTrendData: {
      trendData: generateMockTrendData(days),
    },
  };
}

// ---------------------------------------------------------------------------
// Chart helpers
// ---------------------------------------------------------------------------

/** Build an ASCII sparkline from an array of numeric values */
function sparkline(values) {
  if (!values.length) return '';
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  return values.map(v => {
    const idx = Math.round(((v - min) / range) * (SPARK_CHARS.length - 1));
    return SPARK_CHARS[idx];
  }).join('');
}

/** Build a horizontal bar chart line */
function barLine(label, value, maxValue, barWidth = 40) {
  const filled = maxValue > 0 ? Math.round((value / maxValue) * barWidth) : 0;
  const bar = '█'.repeat(filled) + '░'.repeat(barWidth - filled);
  return `  ${label.padEnd(12)} ${bar} ${value}`;
}

/** Build a multi-line ASCII area chart for a time series */
function asciiChart(values, { width = 70, height = 12, label = '' } = {}) {
  if (!values.length) return '  (no data)';
  const lines = [];

  // Sample values to fit width
  const sampled = sampleArray(values, width);
  const max = Math.max(...sampled, 1);
  const min = Math.min(...sampled, 0);
  const range = max - min || 1;

  if (label) lines.push(`  ${label}`);

  // Build chart rows from top to bottom
  for (let row = height - 1; row >= 0; row--) {
    const threshold = min + (range * (row + 0.5)) / height;
    let line = '';
    for (let col = 0; col < sampled.length; col++) {
      if (sampled[col] >= threshold) {
        // Use different chars for fill vs top of bar
        const nextThreshold = min + (range * (row + 1.5)) / height;
        line += sampled[col] >= nextThreshold ? '│' : '╷';
      } else {
        line += ' ';
      }
    }
    const axisLabel = row === height - 1 ? String(max).padStart(5)
      : row === 0 ? String(Math.round(min)).padStart(5)
      : '     ';
    lines.push(`  ${axisLabel} ┤${line}`);
  }
  lines.push(`        └${'─'.repeat(sampled.length)}`);

  return lines.join('\n');
}

/** Downsample an array to target length */
function sampleArray(arr, targetLen) {
  if (arr.length <= targetLen) return arr;
  const result = [];
  for (let i = 0; i < targetLen; i++) {
    const idx = Math.round((i / (targetLen - 1)) * (arr.length - 1));
    result.push(arr[idx]);
  }
  return result;
}

/** Format a date string for display (shorter) */
function shortDate(dateStr) {
  return dateStr.slice(5); // MM-DD
}

/** Compute percentage change between two values */
function pctChange(oldVal, newVal) {
  if (oldVal === 0) return newVal > 0 ? '+∞' : '0%';
  const pct = ((newVal - oldVal) / oldVal) * 100;
  const sign = pct >= 0 ? '+' : '';
  return `${sign}${pct.toFixed(1)}%`;
}

/** Compute a simple moving average */
function movingAverage(values, window = 7) {
  const result = [];
  for (let i = 0; i < values.length; i++) {
    const start = Math.max(0, i - window + 1);
    const slice = values.slice(start, i + 1);
    result.push(Math.round(slice.reduce((a, b) => a + b, 0) / slice.length));
  }
  return result;
}

/** Detect significant trend direction from a value series */
function detectTrend(values) {
  if (values.length < 7) return { direction: 'insufficient data', magnitude: 0 };
  const firstWeek = values.slice(0, 7);
  const lastWeek = values.slice(-7);
  const firstAvg = firstWeek.reduce((a, b) => a + b, 0) / firstWeek.length;
  const lastAvg = lastWeek.reduce((a, b) => a + b, 0) / lastWeek.length;
  const diff = lastAvg - firstAvg;
  const pct = firstAvg > 0 ? (diff / firstAvg) * 100 : 0;

  if (Math.abs(pct) < 5) return { direction: 'stable', magnitude: pct, firstAvg, lastAvg };
  if (pct < -5) return { direction: 'improving', magnitude: pct, firstAvg, lastAvg };
  return { direction: 'worsening', magnitude: pct, firstAvg, lastAvg };
}

const TREND_ICON = {
  improving: '📉',
  worsening: '📈',
  stable: '➡️',
  'insufficient data': '❓',
};

// ---------------------------------------------------------------------------
// Data processing
// ---------------------------------------------------------------------------

/** Organize raw trend data into structured time series */
function processTrendData(rawData, appFilter) {
  // Filter by app if needed
  let data = rawData;
  if (appFilter) {
    data = data.filter(d => (d.app || '').toLowerCase().includes(appFilter.toLowerCase()));
  }

  // Get unique dates sorted chronologically
  const dates = [...new Set(data.map(d => d.date))].sort();

  // Get unique apps
  const apps = [...new Set(data.filter(d => d.app).map(d => d.app))].sort();

  // Build per-severity total time series
  const bySeverity = {};
  for (const sev of SEV_ORDER) {
    bySeverity[sev] = dates.map(date => {
      return data
        .filter(d => d.date === date && d.severity === sev)
        .reduce((sum, d) => sum + (d.count || 0), 0);
    });
  }

  // Build overall total time series
  const totalSeries = dates.map(date => {
    return data
      .filter(d => d.date === date)
      .reduce((sum, d) => sum + (d.count || 0), 0);
  });

  // Build per-app time series
  const byApp = {};
  for (const app of apps) {
    byApp[app] = {
      total: dates.map(date => {
        return data
          .filter(d => d.date === date && d.app === app)
          .reduce((sum, d) => sum + (d.count || 0), 0);
      }),
      bySeverity: {},
    };
    for (const sev of SEV_ORDER) {
      byApp[app].bySeverity[sev] = dates.map(date => {
        return data
          .filter(d => d.date === date && d.app === app && d.severity === sev)
          .reduce((sum, d) => sum + (d.count || 0), 0);
      });
    }
  }

  // Compute trends
  const trends = {};
  for (const sev of SEV_ORDER) {
    trends[sev] = detectTrend(bySeverity[sev]);
  }
  trends.total = detectTrend(totalSeries);

  const appTrends = {};
  for (const app of apps) {
    appTrends[app] = {
      total: detectTrend(byApp[app].total),
      bySeverity: {},
    };
    for (const sev of SEV_ORDER) {
      appTrends[app].bySeverity[sev] = detectTrend(byApp[app].bySeverity[sev]);
    }
  }

  // Find notable events (spikes, drops)
  const events = findNotableEvents(dates, totalSeries, data);

  return { dates, apps, bySeverity, totalSeries, byApp, trends, appTrends, events };
}

/** Detect significant spikes and drops in the time series */
function findNotableEvents(dates, totalSeries, rawData) {
  const events = [];
  if (totalSeries.length < 3) return events;

  const ma = movingAverage(totalSeries, 7);

  for (let i = 7; i < totalSeries.length; i++) {
    const deviation = totalSeries[i] - ma[i];
    const pct = ma[i] > 0 ? (deviation / ma[i]) * 100 : 0;

    if (pct > 20) {
      // Significant spike — find which severity contributed most
      const dayData = rawData.filter(d => d.date === dates[i]);
      const prevDayData = rawData.filter(d => d.date === dates[i - 1]);
      const sevChanges = SEV_ORDER.map(sev => {
        const curr = dayData.filter(d => d.severity === sev).reduce((s, d) => s + d.count, 0);
        const prev = prevDayData.filter(d => d.severity === sev).reduce((s, d) => s + d.count, 0);
        return { sev, change: curr - prev };
      }).filter(s => s.change > 0).sort((a, b) => b.change - a.change);

      events.push({
        type: 'spike',
        date: dates[i],
        value: totalSeries[i],
        deviation: pct.toFixed(1),
        contributors: sevChanges.slice(0, 2),
      });
    } else if (pct < -20) {
      events.push({
        type: 'drop',
        date: dates[i],
        value: totalSeries[i],
        deviation: pct.toFixed(1),
      });
    }
  }

  // Deduplicate consecutive events of same type
  const deduped = [];
  for (const e of events) {
    const prev = deduped[deduped.length - 1];
    if (prev && prev.type === e.type && prev.date >= dates[dates.indexOf(e.date) - 3]) continue;
    deduped.push(e);
  }

  return deduped.slice(0, 10); // cap at 10 notable events
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

function generateMarkdown(analysis, meta) {
  const { dates, apps, bySeverity, totalSeries, byApp, trends, appTrends, events } = analysis;
  const lines = [];

  lines.push('# Vulnerability Trend Report');
  lines.push(`Generated: ${meta.timestamp}`);
  if (meta.mockData) lines.push('**Note: Generated with mock data (no API key configured)**');
  lines.push(`App filter: ${meta.appFilter || 'all'}`);
  lines.push(`Period: ${dates[0]} to ${dates[dates.length - 1]} (${dates.length} days)`);
  lines.push('');

  // Executive summary
  lines.push('## Executive Summary');
  lines.push('');
  const latestTotal = totalSeries[totalSeries.length - 1];
  const firstTotal = totalSeries[0];
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Period | ${dates[0]} → ${dates[dates.length - 1]} |`);
  lines.push(`| Current total issues | ${latestTotal} |`);
  lines.push(`| Starting total issues | ${firstTotal} |`);
  lines.push(`| Net change | ${latestTotal - firstTotal} (${pctChange(firstTotal, latestTotal)}) |`);
  lines.push(`| Overall trend | ${TREND_ICON[trends.total.direction]} ${trends.total.direction} |`);
  lines.push(`| Applications tracked | ${apps.length} |`);
  lines.push(`| Notable events | ${events.length} |`);
  lines.push('');

  // Severity trend overview
  lines.push('## Severity Trends');
  lines.push('');
  lines.push('| Severity | Start | Current | Change | Trend | Sparkline |');
  lines.push('|----------|-------|---------|--------|-------|-----------|');
  for (const sev of SEV_ORDER) {
    const series = bySeverity[sev];
    if (!series.length) continue;
    const first = series[0];
    const last = series[series.length - 1];
    const trend = trends[sev];
    const spark = sparkline(sampleArray(series, 20));
    lines.push(`| ${SEV_ICON[sev]} ${sev} | ${first} | ${last} | ${pctChange(first, last)} | ${TREND_ICON[trend.direction]} ${trend.direction} | ${spark} |`);
  }
  lines.push('');

  // Total issues chart
  lines.push('## Total Issues Over Time');
  lines.push('');
  lines.push('```');
  lines.push(asciiChart(totalSeries, { width: 60, height: 10, label: 'All Issues (total count per day)' }));
  lines.push('```');
  lines.push(`  Period: ${shortDate(dates[0])} → ${shortDate(dates[dates.length - 1])}`);
  lines.push('');

  // Per-severity charts
  lines.push('## Per-Severity Charts');
  lines.push('');
  for (const sev of ['Critical', 'High']) {
    const series = bySeverity[sev];
    if (!series.length || series.every(v => v === 0)) continue;
    lines.push(`### ${SEV_ICON[sev]} ${sev}`);
    lines.push('');
    lines.push('```');
    lines.push(asciiChart(series, { width: 60, height: 8, label: `${sev} issues` }));
    lines.push('```');
    lines.push(`  Period: ${shortDate(dates[0])} → ${shortDate(dates[dates.length - 1])}`);
    lines.push('');

    // 7-day moving average
    const ma = movingAverage(series, 7);
    lines.push(`7-day moving average: ${sparkline(sampleArray(ma, 30))}`);
    lines.push(`  Latest 7-day avg: ${(ma[ma.length - 1]).toFixed(0)} | Peak 7-day avg: ${Math.max(...ma)}`);
    lines.push('');
  }

  // Per-app analysis
  lines.push('## Per-Application Trends');
  lines.push('');
  for (const app of apps) {
    const appData = byApp[app];
    const appTrend = appTrends[app];
    const first = appData.total[0] || 0;
    const last = appData.total[appData.total.length - 1] || 0;

    lines.push(`### ${app}`);
    lines.push('');
    lines.push(`Overall: ${TREND_ICON[appTrend.total.direction]} **${appTrend.total.direction}** (${pctChange(first, last)})`);
    lines.push('');
    lines.push('```');
    lines.push(asciiChart(appData.total, { width: 50, height: 7, label: `${app} — total issues` }));
    lines.push('```');
    lines.push('');

    // Severity breakdown for this app
    lines.push('| Severity | Start | Current | Trend | Sparkline |');
    lines.push('|----------|-------|---------|-------|-----------|');
    for (const sev of SEV_ORDER) {
      const series = appData.bySeverity[sev];
      if (!series || series.every(v => v === 0)) continue;
      const sevFirst = series[0];
      const sevLast = series[series.length - 1];
      const sevTrend = appTrend.bySeverity[sev];
      const spark = sparkline(sampleArray(series, 15));
      lines.push(`| ${SEV_ICON[sev]} ${sev} | ${sevFirst} | ${sevLast} | ${TREND_ICON[sevTrend.direction]} ${sevTrend.direction} | ${spark} |`);
    }
    lines.push('');
  }

  // Notable events
  if (events.length > 0) {
    lines.push('## Notable Events');
    lines.push('');
    lines.push('Significant deviations from the 7-day moving average:');
    lines.push('');
    for (const event of events) {
      const icon = event.type === 'spike' ? '⚠️' : '✅';
      const desc = event.type === 'spike'
        ? `Spike to ${event.value} issues (+${event.deviation}% above average)`
        : `Drop to ${event.value} issues (${event.deviation}% below average)`;
      lines.push(`- ${icon} **${event.date}**: ${desc}`);
      if (event.contributors?.length) {
        const contribs = event.contributors.map(c => `${c.sev} +${c.change}`).join(', ');
        lines.push(`  - Main contributors: ${contribs}`);
      }
    }
    lines.push('');
  }

  // Weekly summary table
  lines.push('## Weekly Summary');
  lines.push('');
  const weeks = [];
  for (let i = 0; i < dates.length; i += 7) {
    const weekDates = dates.slice(i, i + 7);
    const weekValues = totalSeries.slice(i, i + 7);
    const avg = Math.round(weekValues.reduce((a, b) => a + b, 0) / weekValues.length);
    const max = Math.max(...weekValues);
    const min = Math.min(...weekValues);
    weeks.push({ start: weekDates[0], end: weekDates[weekDates.length - 1], avg, max, min });
  }

  lines.push('| Week | Avg Issues | Min | Max | Trend |');
  lines.push('|------|-----------|-----|-----|-------|');
  for (let i = 0; i < weeks.length; i++) {
    const w = weeks[i];
    let weekTrend = '➡️';
    if (i > 0) {
      const diff = w.avg - weeks[i - 1].avg;
      weekTrend = diff > 2 ? '📈' : diff < -2 ? '📉' : '➡️';
    }
    lines.push(`| ${shortDate(w.start)} → ${shortDate(w.end)} | ${w.avg} | ${w.min} | ${w.max} | ${weekTrend} |`);
  }
  lines.push('');

  // Recommendations
  lines.push('## Insights & Recommendations');
  lines.push('');
  const recs = [];
  let recNum = 1;

  // Overall trend recommendation
  if (trends.total.direction === 'worsening') {
    recs.push(`${recNum++}. **Overall vulnerability count is increasing** (${pctChange(firstTotal, latestTotal)}) — review recent dependency updates and new scan findings.`);
  } else if (trends.total.direction === 'improving') {
    recs.push(`${recNum++}. **Overall trend is positive** (${pctChange(firstTotal, latestTotal)}) — continue current remediation efforts.`);
  }

  // Critical trend
  if (trends.Critical?.direction === 'worsening') {
    recs.push(`${recNum++}. **Critical issues are trending up** — prioritize immediate triage of new critical findings.`);
  } else if (trends.Critical?.direction === 'improving') {
    recs.push(`${recNum++}. **Critical issues are decreasing** — good progress on high-priority remediation.`);
  }

  // Per-app recommendations
  for (const app of apps) {
    const appTrend = appTrends[app];
    if (appTrend.total.direction === 'worsening' && appTrend.total.magnitude > 15) {
      recs.push(`${recNum++}. **${app} needs attention** — issues increased by ${pctChange(byApp[app].total[0], byApp[app].total[byApp[app].total.length - 1])} over the period.`);
    }
    if (appTrend.bySeverity.Critical?.direction === 'worsening') {
      recs.push(`${recNum++}. **${app}: Critical issues rising** — investigate root cause of new critical findings.`);
    }
  }

  // Spikes
  const recentSpikes = events.filter(e => e.type === 'spike');
  if (recentSpikes.length > 3) {
    recs.push(`${recNum++}. **Frequent spikes detected** (${recentSpikes.length} events) — consider more frequent scanning and faster remediation cycles.`);
  }

  if (recs.length === 0) {
    recs.push('No significant concerns — vulnerability posture is stable. Continue regular monitoring.');
  }
  lines.push(recs.join('\n\n'));
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[2] || '';
  const days = parseInt(process.env.OX_DAYS || '90', 10);

  console.log('Ox Security — Vulnerability Trend Analyzer');
  console.log('='.repeat(50));
  if (USE_MOCK) {
    console.log('⚠  No API key found — running with mock data');
  }
  console.log(`App filter: ${appFilter || 'all'}`);
  console.log(`Analysis period: ${days} days`);
  console.log('');

  // Step 1: Fetch trend data
  console.log('Step 1: Fetching trend data...');
  let trendResult;

  if (USE_MOCK) {
    trendResult = getMockTrendData(days);
  } else {
    const { GET_ISSUES_TREND } = await import('../queries/issues.js');
    trendResult = await queryFn(GET_ISSUES_TREND, {
      getIssuesInput: { offset: 0, limit: 1000 },
    });
  }

  const rawData = trendResult.getIssuesTrendData.trendData;
  console.log(`  Raw data points: ${rawData.length}`);

  // Step 2: Process and analyze
  console.log('\nStep 2: Analyzing trends...');
  const analysis = processTrendData(rawData, appFilter);
  const { dates, apps, bySeverity, totalSeries, trends, appTrends, events } = analysis;

  console.log(`  Date range: ${dates[0]} to ${dates[dates.length - 1]}`);
  console.log(`  Applications: ${apps.length} (${apps.join(', ')})`);
  console.log(`  Overall trend: ${TREND_ICON[trends.total.direction]} ${trends.total.direction}`);
  console.log('');

  // Print severity trends
  console.log('  Severity Trends:');
  for (const sev of SEV_ORDER) {
    const series = bySeverity[sev];
    if (!series.length) continue;
    const trend = trends[sev];
    const spark = sparkline(sampleArray(series, 25));
    console.log(`    ${SEV_ICON[sev]} ${sev.padEnd(10)} ${spark}  ${TREND_ICON[trend.direction]} ${trend.direction} (${pctChange(series[0], series[series.length - 1])})`);
  }

  // Print total chart
  console.log('\n  Total Issues Chart:');
  console.log(asciiChart(totalSeries, { width: 55, height: 10, label: 'All issues — daily total' }));
  console.log(`    ${shortDate(dates[0])}${''.padEnd(45)}${shortDate(dates[dates.length - 1])}`);

  // Print per-app summary
  console.log('\n  Per-App Summary:');
  for (const app of apps) {
    const appData = analysis.byApp[app];
    const appTrend = appTrends[app];
    const first = appData.total[0] || 0;
    const last = appData.total[appData.total.length - 1] || 0;
    const spark = sparkline(sampleArray(appData.total, 20));
    console.log(`    ${app}: ${spark}  ${TREND_ICON[appTrend.total.direction]} ${first}→${last} (${pctChange(first, last)})`);
  }

  // Print notable events
  if (events.length > 0) {
    console.log(`\n  Notable Events (${events.length}):`);
    for (const event of events.slice(0, 5)) {
      const icon = event.type === 'spike' ? '⚠️ ' : '✅';
      console.log(`    ${icon} ${event.date}: ${event.type} to ${event.value} (${event.deviation}% from avg)`);
    }
    if (events.length > 5) console.log(`    ... and ${events.length - 5} more`);
  }

  // Step 3: Generate outputs
  console.log('\nStep 3: Generating outputs...');
  const timestamp = new Date().toISOString();
  const outDir = `experiments/trends-${timestamp.slice(0, 10)}`;
  mkdirSync(outDir, { recursive: true });

  // JSON output — full analysis data
  const jsonOut = {
    meta: {
      timestamp,
      mockData: USE_MOCK,
      appFilter: appFilter || null,
      days,
      dateRange: { start: dates[0], end: dates[dates.length - 1] },
    },
    summary: {
      totalDataPoints: rawData.length,
      apps: apps.length,
      overallTrend: trends.total,
      currentTotal: totalSeries[totalSeries.length - 1],
      startTotal: totalSeries[0],
    },
    severityTrends: Object.fromEntries(
      SEV_ORDER.map(sev => [sev, {
        trend: trends[sev],
        current: bySeverity[sev][bySeverity[sev].length - 1],
        start: bySeverity[sev][0],
        peak: Math.max(...bySeverity[sev]),
        trough: Math.min(...bySeverity[sev]),
      }])
    ),
    appTrends: Object.fromEntries(
      apps.map(app => [app, {
        trend: appTrends[app].total,
        current: analysis.byApp[app].total[analysis.byApp[app].total.length - 1],
        start: analysis.byApp[app].total[0],
        severities: Object.fromEntries(
          SEV_ORDER.map(sev => [sev, appTrends[app].bySeverity[sev]])
        ),
      }])
    ),
    events,
    timeSeries: {
      dates,
      total: totalSeries,
      bySeverity: Object.fromEntries(SEV_ORDER.map(sev => [sev, bySeverity[sev]])),
    },
  };
  const jsonPath = `${outDir}/trends.json`;
  writeFileSync(jsonPath, JSON.stringify(jsonOut, null, 2));

  // Markdown report
  const meta = { timestamp, mockData: USE_MOCK, appFilter };
  const mdReport = generateMarkdown(analysis, meta);
  const mdPath = `${outDir}/trends-report.md`;
  writeFileSync(mdPath, mdReport);

  // Summary
  console.log('\n' + '='.repeat(50));
  console.log('Trend Analysis Complete');
  console.log('='.repeat(50));
  console.log(`  Period:         ${dates[0]} → ${dates[dates.length - 1]} (${dates.length} days)`);
  console.log(`  Apps:           ${apps.length}`);
  console.log(`  Data points:    ${rawData.length}`);
  console.log(`  Overall trend:  ${TREND_ICON[trends.total.direction]} ${trends.total.direction}`);
  console.log(`  Notable events: ${events.length}`);
  console.log('');
  console.log(`  JSON:   ${jsonPath}`);
  console.log(`  Report: ${mdPath}`);
}

main().catch(e => { console.error(`\nFatal: ${e.message}`); process.exit(1); });
