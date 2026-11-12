(function() {
  var FONT_PX = 10;
  var CHAR_PX = 5.8;

  function esc(value) {
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function num(value) {
    var parsed = Number(value);
    return isFinite(parsed) ? parsed : 0;
  }

  function fixed(value) {
    return (Math.round(value * 100) / 100).toString();
  }

  function niceStep(span, count, integer) {
    var raw = span / Math.max(1, count);
    var magnitude = Math.pow(10, Math.floor(Math.log(raw) / Math.LN10));
    var ratio = raw / magnitude;
    var step = (ratio <= 1 ? 1 : ratio <= 2 ? 2 : ratio <= 5 ? 5 : 10) * magnitude;
    return integer ? Math.max(1, Math.round(step)) : step;
  }

  function buildScale(values, options) {
    options = options || {};
    var ticksOptions = options.ticks || {};
    var low = values.length ? Math.min.apply(null, values) : 0;
    var high = values.length ? Math.max.apply(null, values) : 1;
    if (options.beginAtZero || options.stacked) low = Math.min(0, low);
    var fixedMin = typeof options.min === 'number';
    var fixedMax = typeof options.max === 'number';
    if (fixedMin) low = options.min;
    if (fixedMax) high = options.max;
    if (high <= low) high = low + 1;
    var limit = ticksOptions.maxTicksLimit || 6;
    var step = niceStep(high - low, limit - 1, ticksOptions.precision === 0);
    if (!fixedMin) low = Math.floor(low / step) * step;
    if (!fixedMax) high = Math.ceil(high / step) * step;
    var ticks = [];
    var first = Math.ceil(low / step - 1e-9) * step;
    for (var tick = first; tick <= high + step * 1e-6 && ticks.length < 50; tick += step) {
      ticks.push(Math.abs(tick) < step * 1e-9 ? 0 : parseFloat(tick.toPrecision(12)));
    }
    var format = function(value) {
      if (typeof ticksOptions.callback === 'function') return String(ticksOptions.callback(value));
      return (Math.round(value * 1000) / 1000).toLocaleString();
    };
    return { min: low, max: high, ticks: ticks, format: format };
  }

  function colorAt(color, index) {
    return Array.isArray(color) ? (color[index] || color[0] || '#008ef7') : (color || '#008ef7');
  }

  function SvgChart(host, config) {
    this.host = host;
    this.config = config || {};
    this.type = this.config.type || 'line';
    this.data = this.config.data || { labels: [], datasets: [] };
    this.options = this.config.options || {};
    this.layout = null;
    host.classList.add('svg-chart');
    host.innerHTML = '';
    this.legendEl = document.createElement('div');
    this.legendEl.className = 'svg-chart-legend';
    this.plotEl = document.createElement('div');
    this.plotEl.className = 'svg-chart-plot';
    this.tipEl = document.createElement('div');
    this.tipEl.className = 'svg-chart-tip';
    this.tipEl.hidden = true;
    var legend = this.legendOptions();
    if (legend.position === 'bottom') {
      host.appendChild(this.plotEl);
      host.appendChild(this.legendEl);
    } else {
      host.appendChild(this.legendEl);
      host.appendChild(this.plotEl);
    }
    host.appendChild(this.tipEl);
    var self = this;
    this.plotEl.addEventListener('pointermove', function(event) { self.hover(event); });
    this.plotEl.addEventListener('pointerdown', function(event) { self.hover(event); });
    this.plotEl.addEventListener('pointerleave', function() { self.clearHover(); });
    if (typeof ResizeObserver !== 'undefined') {
      this.observer = new ResizeObserver(function() {
        var width = self.plotEl.clientWidth;
        var height = self.plotEl.clientHeight;
        if (width !== self.renderedWidth || height !== self.renderedHeight) self.render();
      });
      this.observer.observe(this.plotEl);
    }
    this.render();
  }

  SvgChart.prototype.pluginOptions = function(name) {
    return (this.options.plugins || {})[name] || {};
  };

  SvgChart.prototype.legendOptions = function() {
    var legend = this.pluginOptions('legend');
    return { display: legend.display !== false && this.type !== 'doughnut', position: legend.position || 'top' };
  };

  SvgChart.prototype.update = function() { this.render(); };
  SvgChart.prototype.resize = function() { this.render(); };

  SvgChart.prototype.destroy = function() {
    if (this.observer) this.observer.disconnect();
    this.host.innerHTML = '';
  };

  SvgChart.prototype.datasets = function() {
    return (this.data.datasets || []).map(function(dataset) {
      return dataset || { data: [] };
    });
  };

  SvgChart.prototype.renderLegend = function() {
    var legend = this.legendOptions();
    var datasets = this.datasets().filter(function(dataset) { return dataset.label; });
    if (!legend.display || !datasets.length) {
      this.legendEl.hidden = true;
      this.legendEl.innerHTML = '';
      return;
    }
    this.legendEl.hidden = false;
    this.legendEl.innerHTML = datasets.map(function(dataset) {
      var color = dataset.borderColor || colorAt(dataset.backgroundColor, 0);
      return '<span class="svg-chart-key"><i style="background:' + esc(color) + '"></i>' + esc(dataset.label) + '</span>';
    }).join('');
  };

  SvgChart.prototype.render = function() {
    this.clearHover();
    this.renderLegend();
    var width = this.plotEl.clientWidth;
    var height = this.plotEl.clientHeight;
    this.renderedWidth = width;
    this.renderedHeight = height;
    this.layout = null;
    if (width < 8 || height < 8) {
      this.plotEl.innerHTML = '';
      return;
    }
    var body = this.type === 'doughnut' ? this.renderGauge(width, height) : this.renderCartesian(width, height);
    var label = this.host.getAttribute('aria-label');
    this.plotEl.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="' + height +
      '" viewBox="0 0 ' + width + ' ' + height + '"' + (label ? ' role="img" aria-label="' + esc(label) + '"' : ' aria-hidden="true"') + '>' +
      body + '<g class="svg-chart-hover"></g></svg>';
  };

  SvgChart.prototype.renderGauge = function(width, height) {
    var dataset = this.datasets()[0] || { data: [0] };
    var value = Math.max(0, Math.min(100, num((dataset.data || [])[0])));
    var colors = dataset.backgroundColor || [];
    var size = Math.min(width, height);
    var stroke = Math.max(6, size * 0.11);
    var radius = size / 2 - stroke / 2 - 1;
    var circumference = 2 * Math.PI * radius;
    var cx = width / 2;
    var cy = height / 2;
    var warn = this.pluginOptions('gaugeCenter').warnValue;
    var over = warn && value > warn;
    return '<circle class="svg-chart-track" cx="' + cx + '" cy="' + cy + '" r="' + fixed(radius) + '" fill="none" stroke-width="' + fixed(stroke) + '"/>' +
      '<circle cx="' + cx + '" cy="' + cy + '" r="' + fixed(radius) + '" fill="none" stroke="' + esc(colorAt(colors, 0)) + '" stroke-width="' + fixed(stroke) +
      '" stroke-linecap="round" stroke-dasharray="' + fixed(circumference * value / 100) + ' ' + fixed(circumference) +
      '" transform="rotate(-90 ' + cx + ' ' + cy + ')"/>' +
      '<text class="svg-chart-gauge-value' + (over ? ' is-over' : '') + '" x="' + cx + '" y="' + cy + '" text-anchor="middle" dominant-baseline="central">' +
      esc(num((dataset.data || [])[0]).toFixed(1)) + '%</text>';
  };

  SvgChart.prototype.renderCartesian = function(width, height) {
    var self = this;
    var scales = this.options.scales || {};
    var labels = this.data.labels || [];
    var datasets = this.datasets();
    var horizontal = this.options.indexAxis === 'y';
    var count = labels.length;
    datasets.forEach(function(dataset) { count = Math.max(count, (dataset.data || []).length); });
    var hasData = datasets.some(function(dataset) { return (dataset.data || []).length > 0; });
    var empty = this.pluginOptions('emptyState');
    var valueAxisDefault = horizontal ? 'x' : 'y';
    var categoryOptions = scales[horizontal ? 'y' : 'x'] || {};
    var series = datasets.map(function(dataset, index) {
      var kind = dataset.type || self.type;
      var axisId = horizontal ? 'x' : (dataset.yAxisID || 'y');
      return { dataset: dataset, index: index, kind: kind, axisId: axisId, values: (dataset.data || []).map(num), base: [], top: [] };
    });
    var axisIds = [];
    series.forEach(function(entry) { if (axisIds.indexOf(entry.axisId) === -1) axisIds.push(entry.axisId); });
    if (!axisIds.length) axisIds.push(valueAxisDefault);
    var axes = {};
    axisIds.forEach(function(axisId) {
      var options = scales[axisId] || {};
      var members = series.filter(function(entry) { return entry.axisId === axisId; });
      var stacked = Boolean(options.stacked);
      var extent = [];
      var totals = [];
      members.forEach(function(entry) {
        entry.values.forEach(function(value, i) {
          var base = stacked ? (totals[i] || 0) : 0;
          entry.base[i] = base;
          entry.top[i] = base + value;
          totals[i] = entry.top[i];
          extent.push(entry.top[i]);
        });
        entry.stacked = stacked;
      });
      var scaleOptions = options;
      if (members.some(function(entry) { return entry.kind === 'bar'; }) && !options.beginAtZero) {
        scaleOptions = Object.assign({}, options, { beginAtZero: true });
      }
      axes[axisId] = { id: axisId, options: options, scale: buildScale(extent, scaleOptions), display: options.display !== false, right: options.position === 'right' };
    });
    var categoryDisplay = categoryOptions.display !== false;
    var valueAxes = axisIds.map(function(axisId) { return axes[axisId]; });
    var tickWidth = function(axis) {
      var widest = 0;
      axis.scale.ticks.forEach(function(tick) { widest = Math.max(widest, axis.scale.format(tick).length); });
      return Math.ceil(widest * CHAR_PX) + 8;
    };
    var left = 0;
    var right = 0;
    var top = 0;
    var bottom = 0;
    var truncate = function(text, max) {
      text = String(text === null || text === undefined ? '' : text);
      return text.length > max ? text.slice(0, max - 1) + '…' : text;
    };
    var categoryLabelMax = Math.max(6, Math.floor(Math.min(150, width * 0.38) / CHAR_PX));
    if (horizontal) {
      if (categoryDisplay) {
        var widest = 0;
        labels.forEach(function(label) { widest = Math.max(widest, truncate(label, categoryLabelMax).length); });
        left = Math.ceil(widest * CHAR_PX) + 10;
      }
      if (valueAxes[0].display) {
        bottom = FONT_PX + 8;
        right = 12;
        top = 4;
      }
    } else {
      valueAxes.forEach(function(axis) {
        if (!axis.display) return;
        if (axis.right) right = Math.max(right, tickWidth(axis));
        else left = Math.max(left, tickWidth(axis));
      });
      if (categoryDisplay) bottom = FONT_PX + 8;
      if (left || right || bottom) {
        top = 6;
        right = Math.max(right, 8);
      }
    }
    var plot = { x: left, y: top, w: Math.max(1, width - left - right), h: Math.max(1, height - top - bottom) };
    var out = [];
    var barSeries = series.filter(function(entry) { return entry.kind === 'bar'; });
    var banded = barSeries.length > 0;
    var band = (horizontal ? plot.h : plot.w) / Math.max(1, count);
    var position = function(i) {
      if (banded) return (horizontal ? plot.y : plot.x) + band * (i + 0.5);
      return plot.x + (count > 1 ? plot.w * i / (count - 1) : plot.w / 2);
    };
    var valueToPixel = function(axis, value) {
      var ratio = (value - axis.scale.min) / (axis.scale.max - axis.scale.min);
      ratio = Math.max(0, Math.min(1, ratio));
      return horizontal ? plot.x + plot.w * ratio : plot.y + plot.h * (1 - ratio);
    };

    valueAxes.forEach(function(axis, axisIndex) {
      if (!axis.display) return;
      var grid = (axis.options.grid || {}).display !== false;
      axis.scale.ticks.forEach(function(tick) {
        var at = valueToPixel(axis, tick);
        var text = esc(axis.scale.format(tick));
        if (horizontal) {
          if (grid) out.push('<line class="svg-chart-grid" x1="' + fixed(at) + '" x2="' + fixed(at) + '" y1="' + plot.y + '" y2="' + (plot.y + plot.h) + '"/>');
          out.push('<text class="svg-chart-tick" x="' + fixed(at) + '" y="' + (plot.y + plot.h + FONT_PX + 4) + '" text-anchor="middle">' + text + '</text>');
        } else {
          if (grid && axisIndex === 0) out.push('<line class="svg-chart-grid" x1="' + plot.x + '" x2="' + (plot.x + plot.w) + '" y1="' + fixed(at) + '" y2="' + fixed(at) + '"/>');
          if (axis.right) out.push('<text class="svg-chart-tick" x="' + (plot.x + plot.w + 5) + '" y="' + fixed(at) + '" dominant-baseline="central">' + text + '</text>');
          else out.push('<text class="svg-chart-tick" x="' + (plot.x - 5) + '" y="' + fixed(at) + '" text-anchor="end" dominant-baseline="central">' + text + '</text>');
        }
      });
    });

    if (categoryDisplay && count > 0) {
      if (horizontal) {
        labels.forEach(function(label, i) {
          out.push('<text class="svg-chart-tick" x="' + (plot.x - 6) + '" y="' + fixed(position(i)) + '" text-anchor="end" dominant-baseline="central">' + esc(truncate(label, categoryLabelMax)) + '</text>');
        });
      } else {
        var widestLabel = 1;
        labels.forEach(function(label) { widestLabel = Math.max(widestLabel, String(label).length); });
        var fit = Math.max(1, Math.floor(plot.w / (widestLabel * CHAR_PX + 14)));
        var limit = Math.min(fit, (categoryOptions.ticks || {}).maxTicksLimit || 11, count);
        var stride = Math.max(1, Math.ceil(count / limit));
        for (var i = 0; i < count; i += stride) {
          var at = position(i);
          var anchor = !banded && i === 0 ? 'start' : (!banded && i === count - 1 ? 'end' : 'middle');
          out.push('<text class="svg-chart-tick" x="' + fixed(at) + '" y="' + (plot.y + plot.h + FONT_PX + 5) + '" text-anchor="' + anchor + '">' + esc(labels[i]) + '</text>');
        }
      }
    }

    var groupSlots = {};
    var slotCount = 0;
    barSeries.forEach(function(entry) {
      var key = entry.stacked ? 'stack:' + entry.axisId : 'bar:' + entry.index;
      if (groupSlots[key] === undefined) groupSlots[key] = slotCount++;
      entry.slot = groupSlots[key];
    });
    var groupSize = band * (count > 40 ? 0.9 : 0.72);
    var barSize = slotCount ? Math.max(1, groupSize / slotCount) : 0;
    barSeries.forEach(function(entry) {
      var axis = axes[entry.axisId];
      var radius = Math.min(num(entry.dataset.borderRadius), barSize / 2);
      entry.values.forEach(function(value, i) {
        var from = valueToPixel(axis, entry.base[i]);
        var to = valueToPixel(axis, entry.top[i]);
        var length = Math.abs(to - from);
        if (length <= 0) return;
        var offset = position(i) - groupSize / 2 + entry.slot * barSize;
        var fill = esc(colorAt(entry.dataset.backgroundColor, i));
        var rounding = entry.stacked ? 0 : Math.min(radius, length / 2);
        if (horizontal) {
          out.push('<rect x="' + fixed(Math.min(from, to)) + '" y="' + fixed(offset) + '" width="' + fixed(length) + '" height="' + fixed(barSize) + '" rx="' + fixed(rounding) + '" fill="' + fill + '"/>');
        } else {
          out.push('<rect x="' + fixed(offset) + '" y="' + fixed(Math.min(from, to)) + '" width="' + fixed(barSize) + '" height="' + fixed(length) + '" rx="' + fixed(rounding) + '" fill="' + fill + '"/>');
        }
      });
    });

    var points = [];
    series.forEach(function(entry) {
      points[entry.index] = [];
      if (entry.kind !== 'line' || horizontal || !entry.values.length) return;
      var axis = axes[entry.axisId];
      var topLine = entry.values.map(function(_, i) { return [position(i), valueToPixel(axis, entry.top[i])]; });
      points[entry.index] = topLine;
      var path = function(list) {
        return list.map(function(point) { return fixed(point[0]) + ',' + fixed(point[1]); }).join('L');
      };
      var color = esc(entry.dataset.borderColor || '#008ef7');
      if (entry.dataset.fill) {
        var floor = entry.values.map(function(_, i) {
          return [position(i), valueToPixel(axis, entry.stacked ? entry.base[i] : Math.max(axis.scale.min, Math.min(0, axis.scale.max)))];
        }).reverse();
        out.push('<path d="M' + path(topLine) + 'L' + path(floor) + 'Z" fill="' + esc(entry.dataset.backgroundColor || color) + '" stroke="none"/>');
      }
      if (topLine.length === 1) {
        out.push('<circle cx="' + fixed(topLine[0][0]) + '" cy="' + fixed(topLine[0][1]) + '" r="2.5" fill="' + color + '"/>');
      } else {
        out.push('<path d="M' + path(topLine) + '" fill="none" stroke="' + color + '" stroke-width="' + num(entry.dataset.borderWidth || 1.5) + '" stroke-linejoin="round" stroke-linecap="round"/>');
      }
      var pointRadius = num(entry.dataset.pointRadius);
      if (pointRadius > 0 && topLine.length <= 80) {
        topLine.forEach(function(point) {
          out.push('<circle cx="' + fixed(point[0]) + '" cy="' + fixed(point[1]) + '" r="' + pointRadius + '" fill="' + color + '"/>');
        });
      }
    });

    if (!hasData && !empty.disabled) {
      out.push('<text class="svg-chart-empty" x="' + fixed(plot.x + plot.w / 2) + '" y="' + fixed(plot.y + plot.h / 2) + '" text-anchor="middle" dominant-baseline="central">' +
        esc(empty.message || 'No data in this range yet') + '</text>');
    }

    this.layout = {
      plot: plot, count: hasData ? count : 0, horizontal: horizontal, banded: banded, band: band,
      position: position, series: series, axes: axes, points: points
    };
    return out.join('');
  };

  SvgChart.prototype.clearHover = function() {
    this.tipEl.hidden = true;
    var group = this.plotEl.querySelector('.svg-chart-hover');
    if (group) group.innerHTML = '';
  };

  SvgChart.prototype.tooltipLines = function(index) {
    var self = this;
    var layout = this.layout;
    var callbacks = (this.pluginOptions('tooltip').callbacks) || {};
    var labels = this.data.labels || [];
    var items = layout.series.filter(function(entry) { return index < entry.values.length; }).map(function(entry) {
      return {
        dataIndex: index, datasetIndex: entry.index, dataset: entry.dataset, label: labels[index],
        parsed: { x: entry.values[index], y: entry.values[index] }, entry: entry
      };
    });
    var title = typeof callbacks.title === 'function' ? callbacks.title(items) : labels[index];
    var rows = [];
    items.forEach(function(item) {
      var color = item.dataset.borderColor || colorAt(item.dataset.backgroundColor, index);
      var text;
      if (typeof callbacks.label === 'function') {
        text = callbacks.label(item);
      } else {
        var axis = layout.axes[item.entry.axisId];
        text = (item.dataset.label ? item.dataset.label + ': ' : '') + axis.scale.format(item.entry.values[index]);
      }
      (Array.isArray(text) ? text : [text]).forEach(function(line, lineIndex) {
        rows.push('<div class="svg-chart-tip-row">' + (lineIndex === 0 ? '<i style="background:' + esc(color) + '"></i>' : '<i></i>') + esc(line) + '</div>');
      });
    });
    if (!rows.length) return '';
    return (title === undefined || title === null || title === '' ? '' : '<div class="svg-chart-tip-title">' + esc(title) + '</div>') + rows.join('');
  };

  SvgChart.prototype.hover = function(event) {
    var layout = this.layout;
    if (!layout || !layout.count || this.pluginOptions('tooltip').enabled === false) return;
    var bounds = this.plotEl.getBoundingClientRect();
    var x = event.clientX - bounds.left;
    var y = event.clientY - bounds.top;
    var plot = layout.plot;
    var along = layout.horizontal ? y : x;
    var index;
    if (layout.banded) {
      index = Math.floor((along - (layout.horizontal ? plot.y : plot.x)) / layout.band);
    } else {
      index = layout.count > 1 ? Math.round((along - plot.x) / plot.w * (layout.count - 1)) : 0;
    }
    index = Math.max(0, Math.min(layout.count - 1, index));
    var html = this.tooltipLines(index);
    if (!html) {
      this.clearHover();
      return;
    }
    var at = layout.position(index);
    var marks = [];
    if (layout.horizontal) {
      marks.push('<rect class="svg-chart-band" x="' + plot.x + '" y="' + fixed(at - layout.band / 2) + '" width="' + plot.w + '" height="' + fixed(layout.band) + '"/>');
    } else if (layout.banded) {
      marks.push('<rect class="svg-chart-band" x="' + fixed(at - layout.band / 2) + '" y="' + plot.y + '" width="' + fixed(layout.band) + '" height="' + plot.h + '"/>');
    } else {
      marks.push('<line class="svg-chart-guide" x1="' + fixed(at) + '" x2="' + fixed(at) + '" y1="' + plot.y + '" y2="' + (plot.y + plot.h) + '"/>');
    }
    layout.series.forEach(function(entry) {
      var point = (layout.points[entry.index] || [])[index];
      if (!point) return;
      marks.push('<circle class="svg-chart-dot" cx="' + fixed(point[0]) + '" cy="' + fixed(point[1]) + '" r="' + (num(entry.dataset.pointHoverRadius) || 4) + '" fill="' + esc(entry.dataset.borderColor || '#008ef7') + '"/>');
    });
    var group = this.plotEl.querySelector('.svg-chart-hover');
    if (group) group.innerHTML = marks.join('');
    this.tipEl.innerHTML = html;
    this.tipEl.hidden = false;
    var hostBounds = this.host.getBoundingClientRect();
    var tipWidth = this.tipEl.offsetWidth;
    var tipHeight = this.tipEl.offsetHeight;
    var offsetX = bounds.left - hostBounds.left;
    var offsetY = bounds.top - hostBounds.top;
    var leftPx = x + 14;
    if (leftPx + tipWidth > bounds.width) leftPx = x - tipWidth - 14;
    leftPx = Math.max(0, Math.min(Math.max(0, bounds.width - tipWidth), leftPx));
    var topPx = Math.max(0, Math.min(Math.max(0, bounds.height - tipHeight), y - tipHeight / 2));
    this.tipEl.style.left = (offsetX + leftPx) + 'px';
    this.tipEl.style.top = (offsetY + topPx) + 'px';
  };

  window.SvgChart = SvgChart;
})();
