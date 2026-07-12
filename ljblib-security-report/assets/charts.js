(function() {
  var style = getComputedStyle(document.documentElement);
  var accent = style.getPropertyValue('--accent').trim();
  var accent2 = style.getPropertyValue('--accent2').trim();
  var ink = style.getPropertyValue('--ink').trim();
  var muted = style.getPropertyValue('--muted').trim();
  var rule = style.getPropertyValue('--rule').trim();
  var bg2 = style.getPropertyValue('--bg2').trim();
  var warn = style.getPropertyValue('--warn').trim();
  var ok = style.getPropertyValue('--ok').trim();

  // --- Chart 1: 双站点漏洞对比 ---
  var chart1 = echarts.init(document.getElementById('chart-compare'), null, { renderer: 'svg' });
  chart1.setOption({
    animation: false,
    tooltip: { appendToBody: true },
    legend: { bottom: 0, textStyle: { color: muted, fontSize: 12 } },
    grid: { left: '3%', right: '5%', top: '8%', bottom: '18%' },
    xAxis: {
      type: 'category', data: ['严重', '高危', '中危', '低危'],
      axisLabel: { color: ink, fontSize: 12 }, axisLine: { lineStyle: { color: rule } }
    },
    yAxis: { type: 'value', axisLabel: { color: muted }, splitLine: { lineStyle: { color: rule } } },
    series: [
      { name: 'ljbljb.com', type: 'bar', data: [0, 0, 4, 5], itemStyle: { color: accent }, barWidth: '30%' },
      { name: 'ljblib.xyz', type: 'bar', data: [0, 0, 4, 5], itemStyle: { color: warn }, barWidth: '30%' }
    ]
  });
  window.addEventListener('resize', function() { chart1.resize(); });

  // --- Chart 2: OWASP分类 ---
  var chart2 = echarts.init(document.getElementById('chart-owasp'), null, { renderer: 'svg' });
  chart2.setOption({
    animation: false,
    tooltip: { appendToBody: true, trigger: 'item' },
    series: [{
      type: 'pie', radius: ['35%', '65%'], center: ['50%', '50%'],
      label: { color: ink, fontSize: 12 },
      data: [
        { value: 8, name: 'A05:2021-安全配置错误', itemStyle: { color: accent } },
        { value: 10, name: 'A04:2021-不安全设计', itemStyle: { color: muted } }
      ]
    }]
  });
  window.addEventListener('resize', function() { chart2.resize(); });

  // --- Chart 3: 修复前后对比 ---
  var chart3 = echarts.init(document.getElementById('chart-before-after'), null, { renderer: 'svg' });
  chart3.setOption({
    animation: false,
    tooltip: { appendToBody: true },
    legend: { bottom: 0, textStyle: { color: muted, fontSize: 12 } },
    grid: { left: '3%', right: '5%', top: '8%', bottom: '18%' },
    xAxis: {
      type: 'category', data: ['严重', '高危', '中危', '低危'],
      axisLabel: { color: ink, fontSize: 12 }, axisLine: { lineStyle: { color: rule } }
    },
    yAxis: { type: 'value', name: '漏洞数', nameTextStyle: { color: muted }, axisLabel: { color: muted }, splitLine: { lineStyle: { color: rule } } },
    series: [
      { name: '修复前', type: 'bar', data: [0, 0, 8, 10], itemStyle: { color: accent2 }, barWidth: '30%' },
      { name: '修复后(预期)', type: 'bar', data: [0, 0, 0, 0], itemStyle: { color: ok }, barWidth: '30%' }
    ]
  });
  window.addEventListener('resize', function() { chart3.resize(); });

  // --- Chart 4: 修复优先级矩阵 ---
  var chart4 = echarts.init(document.getElementById('chart-priority'), null, { renderer: 'svg' });
  chart4.setOption({
    animation: false,
    tooltip: { appendToBody: true, formatter: function(p) {
      return p.data.name + '<br/>CVSS: ' + p.data.value[1] + ' | 影响站点: ' + p.data.value[2];
    }},
    grid: { left: '10%', right: '10%', top: '10%', bottom: '15%' },
    xAxis: {
      type: 'value', name: '优先级 (P0=最高)', nameTextStyle: { color: muted },
      min: 0, max: 4, axisLabel: { color: muted }, splitLine: { lineStyle: { color: rule } },
      inverse: true
    },
    yAxis: {
      type: 'value', name: 'CVSS评分', nameTextStyle: { color: muted },
      min: 0, max: 10, axisLabel: { color: muted }, splitLine: { lineStyle: { color: rule } }
    },
    series: [{
      type: 'scatter',
      symbolSize: function(d) { return 20 + d[2] * 8; },
      data: [
        { name: 'P0: HSTS', value: [0, 5.5, 2], itemStyle: { color: accent2 } },
        { name: 'P0: CSP', value: [0, 5.0, 2], itemStyle: { color: accent } },
        { name: 'P0: X-Frame', value: [0, 5.0, 2], itemStyle: { color: accent } },
        { name: 'P1: 版本暴露', value: [1, 3.0, 2], itemStyle: { color: warn } },
        { name: 'P2: 其他头部', value: [2, 2.9, 4], itemStyle: { color: muted } }
      ],
      label: { show: true, formatter: '{b}', position: 'top', color: ink, fontSize: 11 }
    }]
  });
  window.addEventListener('resize', function() { chart4.resize(); });
})();
