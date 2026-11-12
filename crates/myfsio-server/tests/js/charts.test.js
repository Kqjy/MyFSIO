const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function element() {
  return {
    children: [],
    hidden: false,
    innerHTML: '',
    style: {},
    clientWidth: 600,
    clientHeight: 240,
    offsetWidth: 120,
    offsetHeight: 40,
    hover: { innerHTML: '' },
    classList: { add() {} },
    appendChild(child) { this.children.push(child); },
    addEventListener() {},
    getAttribute() { return null; },
    querySelector() { return this.hover; },
    getBoundingClientRect() { return { left: 0, top: 0, width: 600, height: 240 }; }
  };
}

const window = {};
const context = vm.createContext({ window, document: { createElement: element } });
vm.runInContext(fs.readFileSync(path.join(__dirname, '../../static/js/charts.js'), 'utf8'), context);
const SvgChart = window.SvgChart;

function tickLabels(chart) {
  return Array.from(chart.plotEl.innerHTML.matchAll(/<text class="svg-chart-tick"[^>]*text-anchor="end" dominant-baseline="central">([^<]*)<\/text>/g)).map(function(match) { return match[1]; });
}

function linePaths(chart) {
  return Array.from(chart.plotEl.innerHTML.matchAll(/<path d="([^"]+)" fill="none"/g)).map(function(match) { return match[1]; });
}

function missingBucketHistoryLeavesAGap() {
  const chart = new SvgChart(element(), {
    type: 'line',
    data: {
      labels: ['10:00', '10:05', '10:10'],
      datasets: [{ label: 'example-bucket', data: [null, 1000000, 1100000], borderColor: '#10b981', fill: 'origin' }]
    },
    options: {
      plugins: {
        tooltip: {
          callbacks: {
            title: function(items) { return 'sample ' + items[0].dataIndex; },
            label: function(item) { return item.dataset.label + ': ' + item.parsed.y; }
          }
        }
      },
      scales: { y: { stacked: true, beginAtZero: true } }
    }
  });
  const series = chart.layout.series[0];
  assert.deepStrictEqual(Array.from(series.values), [null, 1000000, 1100000]);
  assert.strictEqual(chart.layout.points[0][0], null);
  const paths = linePaths(chart);
  assert.strictEqual(paths.length, 1);
  assert.strictEqual(paths[0].split('L').length, 2);
  const firstX = Number(paths[0].slice(1).split(',')[0]);
  assert.ok(firstX > chart.layout.position(0) + 1);
  const missing = chart.tooltipLines(0);
  assert.ok(missing.includes('No data recorded'));
  assert.ok(!missing.includes('example-bucket'));
  assert.ok(missing.includes('sample 0'));
  assert.ok(chart.tooltipLines(1).includes('example-bucket: 1000000'));
}

function missingSamplesDoNotStackAsZero() {
  const chart = new SvgChart(element(), {
    type: 'line',
    data: {
      labels: ['a', 'b', 'c'],
      datasets: [
        { label: 'one', data: [null, 5, 5], borderColor: '#111111' },
        { label: 'two', data: [3, null, 3], borderColor: '#222222' }
      ]
    },
    options: { scales: { y: { stacked: true, beginAtZero: true } } }
  });
  const series = chart.layout.series;
  assert.deepStrictEqual(Array.from(series[0].top), [null, 5, 5]);
  assert.deepStrictEqual(Array.from(series[1].top), [3, null, 8]);
  const first = chart.tooltipLines(0);
  assert.ok(first.includes('two: 3'));
  assert.ok(!first.includes('one'));
  const bars = new SvgChart(element(), {
    type: 'bar',
    data: { labels: ['a', 'b'], datasets: [{ label: 'hits', data: [null, 4], backgroundColor: '#333333' }] },
    options: {}
  });
  assert.strictEqual((bars.plotEl.innerHTML.match(/<rect /g) || []).length, 1);
  assert.ok(bars.tooltipLines(0).includes('No data recorded'));
}

function trendChart(values, tick, value) {
  return new SvgChart(element(), {
    type: 'line',
    data: { labels: ['10:00', '10:05'], datasets: [{ data: values, borderColor: '#3b82f6', fill: true }] },
    options: {
      plugins: { legend: { display: false } },
      scales: { y: { display: true, beginAtZero: true, valueFormat: value, ticks: { callback: tick } } }
    }
  });
}

function smallNonzeroValuesKeepPrecision() {
  const rate = trendChart([1 / 300, 2 / 300], SvgChart.tickText, function(v) { return SvgChart.valueText(v) + ' req/s'; });
  assert.ok(rate.tooltipLines(0).includes('0.00333 req/s'));
  assert.ok(rate.tooltipLines(1).includes('0.00667 req/s'));
  const rateTicks = tickLabels(rate);
  assert.ok(rateTicks.length >= 3);
  assert.strictEqual(new Set(rateTicks).size, rateTicks.length);

  const latency = trendChart([0.02, 0.04],
    function(v, step) { return SvgChart.tickText(v, step) + 'ms'; },
    function(v) { return SvgChart.valueText(v) + ' ms'; });
  assert.ok(latency.tooltipLines(0).includes('0.02 ms'));
  assert.ok(latency.tooltipLines(1).includes('0.04 ms'));
  const latencyTicks = tickLabels(latency);
  assert.deepStrictEqual(latencyTicks, ['0.00ms', '0.01ms', '0.02ms', '0.03ms', '0.04ms']);

  const plain = trendChart([0.02, 0.04]);
  assert.ok(plain.tooltipLines(0).includes('0.02'));
  assert.strictEqual(new Set(tickLabels(plain)).size, tickLabels(plain).length);
}

function valueTextKeepsUsefulDigits() {
  assert.strictEqual(SvgChart.valueText(0), '0');
  assert.strictEqual(SvgChart.valueText(0.02), '0.02');
  assert.strictEqual(SvgChart.valueText(0.000123456), '0.000123');
  assert.strictEqual(SvgChart.valueText(1.23456), '1.23');
  assert.strictEqual(SvgChart.valueText(12), '12');
  assert.strictEqual(SvgChart.valueText(1234.56), '1,234.6');
  assert.strictEqual(SvgChart.tickText(2, 1), '2');
  assert.strictEqual(SvgChart.tickText(0.5, 0.5), '0.5');
  assert.strictEqual(SvgChart.tickText(0.005, 0.005), '0.005');
}

missingBucketHistoryLeavesAGap();
missingSamplesDoNotStackAsZero();
smallNonzeroValuesKeepPrecision();
valueTextKeepsUsefulDigits();
