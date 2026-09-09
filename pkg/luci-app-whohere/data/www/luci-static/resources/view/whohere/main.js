'use strict';
'require view';
'require form';
'require uci';
'require rpc';
'require poll';
'require dom';
'require ui';

var callList      = rpc.declare({ object: 'whohere', method: 'list' });
var callDetail    = rpc.declare({ object: 'whohere', method: 'detail', params: ['mac'] });
var callScan      = rpc.declare({ object: 'whohere', method: 'scan' });
var callForget    = rpc.declare({ object: 'whohere', method: 'forget', params: ['mac'] });
var callNote      = rpc.declare({ object: 'whohere', method: 'note', params: ['mac', 'name'] });
var callUpdateOui = rpc.declare({ object: 'whohere', method: 'update_oui' });
var callPortProbe = rpc.declare({ object: 'whohere', method: 'port_probe' });

function fmtTs(ts) {
	ts = parseInt(ts || 0);
	return ts ? new Date(ts * 1000).toLocaleString() : '-';
}

function fmtAge(ts) {
	ts = parseInt(ts || 0);
	if (!ts) return '-';
	var s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
	if (s < 60) return s + ' 秒前';
	if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
	if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
	return Math.floor(s / 86400) + ' 天前';
}

/* 置信度直接用颜色表达, 免得一堆数字看不出轻重 */
function confBadge(c) {
	c = parseInt(c || 0);
	var color = c >= 75 ? '#16a34a' : (c >= 45 ? '#d97706' : '#6b7280');
	var label = c >= 75 ? '高' : (c >= 45 ? '中' : (c > 0 ? '低' : '未知'));
	return E('span', {
		'style': 'display:inline-block;min-width:3.2em;text-align:center;padding:1px 6px;' +
			'border-radius:10px;color:#fff;font-size:90%;white-space:nowrap;background:' + color,
		'title': '置信度 ' + c + '%'
	}, label + (c ? ' ' + c + '%' : ''));
}

function dot(online) {
	return E('span', {
		'style': 'flex:0 0 auto;width:8px;height:8px;border-radius:50%;margin-top:0.45em;' +
			'background:' + (online ? '#16a34a' : '#cbd5e1')
	}, ' ');
}

/* 品牌 + 系统 + 类型, 拼成一行人话 */
/* 纯文本版, 给弹窗和 title 属性用 */
function describe(d) {
	var bits = [];
	if (d.brand) bits.push(d.brand);
	if (d.os && d.os !== d.brand) bits.push(d.os);
	var s = bits.join(' · ');
	if (d.model) s += (s ? ' ' : '') + '(' + d.model + ')';
	if (!s) s = '未识别';
	if (d.platform) s += '  [' + d.platform + ']';
	return s;
}

/* 表格里的「识别结果」单元格。
   后端给的是 brand / os / model / platform 四个独立字段, 早先这里把它们拼成
   一个纯字符串, 于是所有成分同字号同权重、长度全看内容, 一列看下来毫无对齐可言;
   "[Proxmox 宿主机]" 还会被从中间断行成「宿主 / 机]」。这里把结构还原:
   主行放品牌+系统, 型号降为灰色小字, 虚拟化平台做成不换行的徽章。 */
function resultCell(d) {
	var head = [];
	if (d.brand) head.push(d.brand);
	if (d.os && d.os !== d.brand) head.push(d.os);

	var kids = [];
	if (head.length) {
		kids.push(E('span', {}, head.join(' · ')));
	} else {
		kids.push(E('span', { 'style': 'color:#9ca3af' }, '未识别'));
	}
	if (d.model) {
		kids.push(E('span', {
			'style': 'color:#6b7280;font-size:90%;margin-left:.4em;white-space:nowrap'
		}, d.model));
	}

	var rows = [E('div', {}, kids)];
	if (d.platform) {
		rows.push(E('div', { 'style': 'margin-top:2px' },
			E('span', {
				'style': 'display:inline-block;white-space:nowrap;padding:0 6px;' +
					'border-radius:8px;font-size:85%;background:#eef2ff;color:#4338ca',
				'title': '虚拟化平台 —— 只说明它跑在什么上面, 里面装的系统由其它信号决定'
			}, d.platform)));
	}
	return E('div', { 'style': 'line-height:1.5' }, rows);
}

var SRC_LABEL = {
	dhcp55: 'DHCP 指纹',
	dhcp60: 'DHCP 厂商串',
	mdns: 'mDNS',
	ssdp: 'SSDP',
	hostname: '主机名',
	dns: 'DNS',
	stack: 'DNS 行为',
	forwarder: 'DNS 转发',
	sni: 'TLS SNI',
	penalty: '反证',
	peer: '长连对端',
	mqtt: 'MQTT ClientID',
	conns: '长连接',
	tcp: 'TCP 栈指纹',
	ua: 'User-Agent',
	sniff: '被动抓包',
	port: '开放端口',
	banner: '服务 banner',
	ports: '端口探测',
	oui: 'MAC OUI'
};

/* 守护进程只出状态码和参数, 中文文案在这里映射 */
var STATE_LABEL = {
	reading_log:   function (i) { return '正在读取日志: ' + i; },
	listening:     function (i) { return '已监听 ' + i; },
	listen_failed: function (i) { return '监听失败: ' + i; },
	subscribed:    function (i) { return '正在监听 ubus 事件 ' + i; },
	disabled:      function ()  { return '已关闭'; },
	no_iface:      function ()  { return '找不到内网接口'; },
	unsupported:   function ()  { return '当前平台不支持'; },
	reading:       function (i) { return '正在读取 ' + i; },
	unavailable:   function (i) { return '读不到 ' + i + '(内核未启用 conntrack)'; },
	probing:       function (i) { return '正在探测 ' + i + ' 台设备…'; },
	done:          function (i) { return '探测完成 (' + i + ' 台)'; },
	done_redirected: function (i) {
		var a = String(i).split(';');
		return '探测完成 (' + a[0] + ' 台) —— 端口 ' + a[1] +
			' 在几乎所有设备上都"开着", 判定为网络侧的透明劫持' +
			'(DNS 重定向 / 强制门户), 已从结果中剔除';
	}
};

function srcText(s) {
	var f = STATE_LABEL[s.state];
	return f ? f(s.info || '') : (s.state || '') + ' ' + (s.info || '');
}

/* age 是秒数, 文案由界面排 */
function fmtAge2(secs) {
	secs = parseInt(secs || 0);
	if (secs < 3600) return '';
	if (secs < 86400) return ' · ' + Math.floor(secs / 3600) + ' 小时前';
	return ' · ' + Math.floor(secs / 86400) + ' 天前';
}

/* "~" 是后端给的"近似命中"记号 */
function evText(e) {
	if (e.source === 'forwarder') return FORWARDER_TEXT(e.detail);
	var d = String(e.detail || '').replace(/ ~$/, ' (近似)');
	return d + fmtAge2(e.age) +
		(e.kind && KIND_LABEL[e.kind] ? '  [' + KIND_LABEL[e.kind] + ']' : '');
}

var KIND_LABEL = {
	heartbeat: '心跳', service: '云服务', web: '网页(弱)', stack: '统计特征',
	weak: '通用值(弱)'
};

/* forwarder 那条证据的 detail 是厂商列表, 单独排一句人话 */
var FORWARDER_TEXT = function (vendors) {
	return '同时出现多个厂商的心跳域名(' + vendors + '), 在替其它设备转发 DNS';
};

function showDetail(mac) {
	return callDetail(mac).then(function (d) {
		d = d || {};
		/* 判定结果表专用: 空值也要占一行, 显示为"—"。
		   品牌判空和"根本没有品牌这一维"是两回事, 隐藏了就分不出来。 */
		function idRow(k, v) {
			var empty = (v === undefined || v === null || v === '');
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'style': 'width:30%;font-weight:bold' }, k),
				empty
					? E('td', { 'class': 'td left', 'style': 'color:#9ca3af' }, '—')
					: E('td', { 'class': 'td left', 'style': 'word-break:break-all' },
						String(v))
			]);
		}

		function row(k, v) {
			if (v === undefined || v === null || v === '' ||
				(Array.isArray(v) && !v.length)) return null;
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'style': 'width:30%;font-weight:bold' }, k),
				E('td', { 'class': 'td left', 'style': 'word-break:break-all' },
					Array.isArray(v) ? v.join(', ') : String(v))
			]);
		}

		var evRows = (d.evidence || []).map(function (e) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'style': 'width:22%' },
					SRC_LABEL[e.source] || e.source),
				E('td', { 'class': 'td left', 'style': 'word-break:break-all' }, evText(e)),
				E('td', { 'class': 'td left', 'style': 'width:15%' }, '权重 ' + e.weight)
			]);
		});

		var unmatched = Object.keys(d.unmatched || {});

		/* DNS 行为画像: 不看查了什么域名, 只看怎么查。
		   对只查过几个大众域名的设备, 这是唯一还能出结论的一路。 */
		var qt = d.qtypes || {};
		var qtKeys = Object.keys(qt).sort(function (a, b) { return qt[b] - qt[a]; });
		var qtLine = qtKeys.map(function (k) {
			var pct = d.dns_samples ? Math.round(qt[k] * 100 / d.dns_samples) : 0;
			return k + ' ' + qt[k] + ' (' + pct + '%)';
		}).join('   ');

		function pairLine() {
			if (!d.dns_samples) return null;
			return 'A+AAAA ' + Math.round((d.pair_a4 || 0) * 100) + '%' +
				'   A+HTTPS ' + Math.round((d.pair_https || 0) * 100) + '%';
		}

		/* 实测各家系统都是每次查询换一个临时端口(离散度 1.0), 所以这一项
		   只在明显偏低时才有意义 —— 那说明是把端口写死的嵌入式栈。 */
		function portLine() {
			if (d.port_spread === null || d.port_spread === undefined) return null;
			var sp = d.port_spread;
			return sp.toFixed(2) + (sp >= 0.9 ? '  (每次新端口, 常态)'
				: (sp >= 0.35 ? '  (部分复用)' : '  (端口粘死, 嵌入式栈)'));
		}

		ui.showModal(d.name || mac, [
			E('div', { 'style': 'max-height:60vh;overflow:auto' }, [
				E('h4', {}, '判定结果'),
				E('table', { 'class': 'table' }, [
					idRow('品牌', d.brand),
					idRow('系统', d.os),
					idRow('型号', d.model),
					idRow('设备类型', d.type),
					idRow('虚拟化平台', d.platform),
					idRow('随机 MAC', d.random_mac ? '是 (OUI 不可信)' : '否'),
					idRow('置信度', d.confidence + '%')
				]),

				E('h4', {}, '判定依据'),
				evRows.length
					? E('table', { 'class': 'table' }, evRows)
					: E('p', { 'style': 'color:#6b7280' },
						'还没有采到任何信号。设备可能刚上线, 或者用了加密 DNS 且不广播 mDNS。'),

				E('h4', {}, '原始信息'),
				E('table', { 'class': 'table' }, [
					row('MAC', d.mac + (d.random_mac ? '  (已随机化, OUI 不可信)' : '')),
					row('IPv4', d.ipv4),
					row('IPv6', d.ipv6),
					row('DHCP 主机名', d.dhcp_name),
					row('静态绑定名', d.static_name),
					row('mDNS 名', d.mdns_name),
					row('mDNS 型号', d.mdns_model),
					row('mDNS 服务', d.mdns_services),
					row('SSDP SERVER', d.upnp_server),
					row('DHCP 厂商串 (opt60)', d.dhcp_vendor),
					row('DHCP 指纹 (opt55)', d.dhcp_fp),
					row('TCP 栈指纹', d.tcp_fp),
					row('开放端口', (d.open_ports || []).map(function (p) {
						return p + '/tcp';
					})),
					row('服务 banner', d.banner),
					row('HTTP User-Agent', d.http_ua),
					row('MQTT ClientID', d.mqtt_id),
					row('网卡厂商 (OUI)', d.oui),
					row('首次发现', fmtTs(d.first_seen)),
					row('最近在线', fmtTs(d.last_seen))
				].filter(Boolean)),

				d.dns_samples ? E('div', {}, [
					E('h4', {}, 'DNS 行为画像'),
					E('p', { 'style': 'color:#6b7280;font-size:90%' },
						'与查了什么域名无关的一路信号。HTTPS(RR 65) 基本只有 Apple 系统栈和' +
						'现代浏览器会查; 同域名的 A/AAAA 紧挨着发出是 Windows 解析器的行为。'),
					E('table', { 'class': 'table' }, [
						row('查询总数', String(d.dns_samples)),
						row('查询类型分布', qtLine),
						row('同域名成对查询', pairLine()),
						row('源端口离散度', portLine())
					].filter(Boolean))
				]) : E('div'),

				unmatched.length ? E('div', {}, [
					E('h4', {}, '未命中的域名样本'),
					E('p', { 'style': 'color:#6b7280;font-size:90%' },
						'这些域名还没有对应规则, 可以据此补规则库。'),
					E('pre', { 'style': 'max-height:150px;overflow:auto' },
						unmatched.map(function (k) { return k + '  ×' + d.unmatched[k]; }).join('\n'))
				]) : E('div')
			]),
			E('div', { 'class': 'right', 'style': 'margin-top:1em' }, [
				E('button', {
					'class': 'btn cbi-button-neutral',
					'click': function () {
						var name = prompt('给这台设备起个名字(留空清除):', d.note || '');
						if (name === null) return;
						callNote(mac, name).then(function () {
							ui.hideModal();
							ui.addNotification(null, E('p', '备注已保存'), 'info');
						});
					}
				}, '设置备注名'),
				' ',
				E('button', {
					'class': 'btn cbi-button-remove',
					'click': function () {
						if (!confirm('从档案中删除这台设备? 它下次上线会被重新发现。')) return;
						callForget(mac).then(function () {
							ui.hideModal();
							ui.addNotification(null, E('p', '已删除'), 'info');
						});
					}
				}, '删除档案'),
				' ',
				E('button', { 'class': 'btn', 'click': ui.hideModal }, '关闭')
			])
		]);
	});
}

function renderTable(data) {
	var devs = (data && data.devices) || [];
	var rows = devs.map(function (d) {
		var nameCell = E('td', { 'class': 'td left' }, [
			E('div', { 'style': 'display:flex;align-items:flex-start;gap:6px' }, [
				dot(d.online),
				E('a', {
					'href': '#',
					'style': 'font-weight:bold',
					'click': function (ev) { ev.preventDefault(); showDetail(d.mac); }
				}, d.name || d.mac)
			])
		]);
		return E('tr', { 'class': 'tr' }, [
			nameCell,
			E('td', { 'class': 'td left' }, (d.ipv4 && d.ipv4[0]) || '-'),
			E('td', { 'class': 'td left', 'style': 'font-family:monospace;font-size:90%;white-space:nowrap' }, [
				E('span', {}, d.mac),
				d.random_mac ? E('span', {
					'style': 'margin-left:6px;padding:0 5px;border-radius:8px;font-size:85%;' +
						'background:#e5e7eb;color:#374151;font-family:sans-serif;white-space:nowrap;' +
						'display:inline-block',
					'title': 'MAC 本地管理位为 1, 是随机化地址, 厂商查询无意义'
				}, '随机') : E('span')
			]),
			E('td', { 'class': 'td left' }, resultCell(d)),
			E('td', { 'class': 'td left', 'style': 'white-space:nowrap' }, d.type || '-'),
			E('td', { 'class': 'td left' }, [confBadge(d.confidence)]),
			E('td', { 'class': 'td left', 'style': 'white-space:nowrap' },
				d.online ? '在线' : fmtAge(d.last_seen))
		]);
	});

	if (!rows.length)
		rows = [E('tr', { 'class': 'tr placeholder' },
			E('td', { 'class': 'td', 'colspan': 7 }, '还没有发现任何设备'))];

	return E('table', { 'class': 'table cbi-section-table' }, [
		E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th left' }, '设备'),
			E('th', { 'class': 'th left' }, 'IP'),
			E('th', { 'class': 'th left' }, 'MAC'),
			E('th', { 'class': 'th left' }, '识别结果'),
			E('th', { 'class': 'th left' }, '类型'),
			E('th', { 'class': 'th left' }, '置信度'),
			E('th', { 'class': 'th left' }, '状态')
		])
	].concat(rows));
}


/* 主动端口探测: 独立区块 + 自己的按钮。
   默认只给三行 —— 是什么、什么时候按、有什么代价; 细节收进「详情」里,
   想看的人再展开。 */
function renderProbePanel(self) {
	var log = E('div', { 'style': 'margin-top:.6em;color:#4b5563;font-size:92%' });

	var more = E('div', {
		'hidden': true,
		'style': 'margin-top:.6em;color:#4b5563;font-size:90%;line-height:1.7;' +
			'border-left:3px solid #e5e7eb;padding-left:.8em'
	}, E('span', {}, ''));
	more.firstChild.innerHTML =
		'固定 33 个端口, 收录标准是「开着就能说明身份」而不是「常见」—— ' +
		'8080、8443 这类什么都可能是的刻意没收。<br>' +
		'22 和 80 会多读一句 banner: <code>SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13</code> ' +
		'里发行版和版本号都写着; HTTP 用 HEAD 取 <code>Server:</code> 头, ' +
		'不会在对方日志里留下"访问了某个页面"。<br>' +
		'单端口超时 0.4 秒, (设备 × 端口) 摊平成队列 32 线程并发, 十几台设备几秒结束。<br>' +
		'结果会做一次透明劫持自检: 某端口若在几乎所有设备上都"开着", 那是网络的属性' +
		'而不是设备的属性(DNS 重定向、强制门户), 整体剔除。';

	var toggle = E('a', {
		'href': '#',
		'style': 'font-size:90%',
		'click': function (ev) {
			ev.preventDefault();
			more.hidden = !more.hidden;
			ev.target.textContent = more.hidden ? '详情' : '收起';
		}
	}, '详情');

	var btn = E('button', {
		'class': 'btn cbi-button-action',
		'click': ui.createHandlerFn(self, function () {
			dom.content(log, '正在探测…');
			return callPortProbe().then(function (r) {
				dom.content(log, (r && r.ok)
					? '已发起。几秒后设备表会自动刷新, 点设备名可以看到开放端口和 banner。'
					: E('span', { 'style': 'color:#dc2626' },
						'未启用 —— 请在「采集设置」里打开「允许主动端口探测」并保存。'));
			});
		})
	}, '开始探测');

	return E('div', {
		'class': 'cbi-section',
		'style': 'border:1px solid #e5e7eb;border-radius:6px;padding:1em;margin:1em 0'
	}, [
		E('div', { 'style': 'display:flex;align-items:center;gap:1em;flex-wrap:wrap' }, [
			E('h3', { 'style': 'margin:0;flex:1 1 auto' }, '主动端口探测'),
			btn
		]),
		(function () {
			var p = E('div', {
				'style': 'color:#4b5563;font-size:92%;line-height:1.7;margin-top:.5em'
			}, E('span', {}, ''));
			p.firstChild.innerHTML =
				'唯一会主动连客户端的一路, 默认关闭, 也不会在后台自己跑。<br>' +
				'<b>某台设备认不出来时按一下</b> —— 专治不广播、也不用本机 DNS 的' +
				'安静设备: 虚拟化宿主机(8006)、NAS、摄像机(554)、打印机(631)。<br>' +
				'<span style="color:#92400e">会在对方日志里留连接记录, ' +
				'别人的网络(公司、校园)上开之前先想清楚。</span>';
			return p;
		})(),
		more,
		E('div', { 'style': 'margin-top:.4em' }, toggle),
		log
	]);
}

/* 统计数字和采集源状态行拆成两块渲染, 好让「主动端口探测」区块插在中间 ——
   它的状态行(· 端口探测: 探测完成…)就紧跟在面板下面, 按钮和它的输出相邻。 */
function renderStats(data) {
	data = data || {};

	function stat(label, value, hint) {
		return E('div', { 'style': 'min-width:9em' }, [
			E('div', { 'style': 'font-size:1.6em;font-weight:bold' }, String(value)),
			E('div', { 'style': 'color:#6b7280;font-size:90%' }, label),
			hint ? E('div', { 'style': 'color:#9ca3af;font-size:85%' }, hint) : E('span')
		]);
	}

	return E('div', { 'style': 'display:flex;gap:2em;flex-wrap:wrap;margin-bottom:1em' }, [
		stat('设备总数', data.total || 0),
		stat('在线', data.online || 0),
		stat('已识别', data.identified || 0, '置信度 ≥50%'),
		stat('OUI 库', data.oui_db || 0, (data.oui_db ? '条' : '未下载'))
	]);
}

function renderSources(data) {
	var st = (data || {}).status || {};
	if (!st.running) {
		return E('div', {}, E('div', { 'style': 'color:#dc2626' },
			'采集进程未运行 —— 只能看到 DHCP 租约和邻居表, 没有指纹识别。'));
	}
	return E('div', {}, (st.sources || []).map(function (s) {
		return E('div', { 'style': 'font-size:90%;color:#4b5563' },
			'· ' + (SRC_LABEL[s.kind] || s.kind) + ': ' + srcText(s));
	}));
}

return view.extend({
	load: function () {
		return Promise.all([
			uci.load('whohere'),
			callList().catch(function () { return {}; })
		]);
	},

	render: function (data) {
		var self = this;
		var listData = (data && data[1]) || {};

		var statsEl = renderStats(listData);
		var srcEl = renderSources(listData);
		var table = renderTable(listData);

		poll.add(function () {
			return callList().then(function (d) {
				// dom.content 不吃 NodeList, 必须转成数组
				dom.content(statsEl,
					Array.prototype.slice.call(renderStats(d).childNodes));
				dom.content(srcEl,
					Array.prototype.slice.call(renderSources(d).childNodes));
				var fresh = renderTable(d);
				dom.content(table.parentNode, fresh);
				table = fresh;
			});
		}, 10);

		var m, s, o;
		m = new form.Map('whohere', null, null);

		s = m.section(form.NamedSection, 'global', 'whohere', '采集设置');
		s.anonymous = true;

		o = s.option(form.Flag, 'enabled', '启用');
		o.rmempty = false;

		o = s.option(form.ListValue, 'dns_source', 'DNS 采集来源',
			'DNS 只是四路信号之一。走 DoH/DoT 的设备这一路必然是空的, ' +
			'它们要靠 DHCP 指纹和 mDNS 来认。');
		o.value('auto', '自动探测');
		o.value('dnsmasq_log', 'dnsmasq 日志');
		o.value('singbox_log', 'sing-box 日志');
		o.value('dnstap', 'dnstap (需 unbound/smartdns, dnsmasq 不支持)');
		o.value('off', '关闭');

		o = s.option(form.Value, 'dns_log', 'dnsmasq 日志路径',
			'必须放在 tmpfs。原始日志读完即截断, 只有命中的规则会被保留。');
		o.depends('dns_source', 'auto');
		o.depends('dns_source', 'dnsmasq_log');

		o = s.option(form.Value, 'singbox_log', 'sing-box 日志路径',
			'需要 sing-box 日志级别为 debug 或以上, 否则日志里没有 DNS 记录。');
		o.depends('dns_source', 'singbox_log');

		o = s.option(form.Flag, 'manage_dnsmasq', '自动配置 dnsmasq',
			'代为打开 logqueries 并挂上 DHCP 钩子。已有自定义配置时会让路不覆盖, ' +
			'卸载时自动还原。');

		o = s.option(form.Flag, 'dhcp_fingerprint', 'DHCP 指纹 (opt55/opt60)',
			'准确率最高的一路, 且不受随机 MAC 和加密 DNS 影响。');

		o = s.option(form.Flag, 'mdns', 'mDNS 监听 (5353)',
			'唯一能直接拿到具体型号的一路, 比如 model=iPhone15,2。');

		o = s.option(form.Flag, 'ssdp', 'SSDP 监听 (1900)');

		o = s.option(form.Flag, 'port_probe', '允许主动端口探测',
			'总开关。打开后, 页面上「主动端口探测」区块的按钮才能发起探测; ' +
			'它本身不会让任何扫描自动发生。');
		o.rmempty = false;

		o = s.option(form.Flag, 'conns', '长连接对端 (conntrack)',
			'读内核的连接跟踪表, 看每台设备常年连着谁的什么端口。' +
			'专治那种开机解析一次 DNS 就再不查、只挂一条长连、也不开监听端口的 IoT 设备 —— ' +
			'前面几路对它们全是空的, 但对端端口躲不掉(向日葵设备的 UDP/12312、' +
			'安卓推送的 TCP/5228、苹果推送的 TCP/5223)。只读不发包。');

		o = s.option(form.Flag, 'sniff', '被动抓包 (TCP 指纹 / TLS SNI)',
			'在内网桥上抓 TCP SYN 和 TLS ClientHello。SYN 里的选项顺序能区分 ' +
			'Windows / Linux / Apple 的协议栈; SNI 是明文的, 于是同一份域名规则库 ' +
			'对走加密 DNS(DoH/DoT)的设备同样生效 —— 那些设备在 DNS 那一路是全空的。 ' +
			'过滤在内核完成, 只有 SYN 和小于 1400 字节的 80/443 请求包会上送。');

		s = m.section(form.NamedSection, 'global', 'whohere', '存储与隐私');
		s.anonymous = true;

		o = s.option(form.Value, 'db', '设备档案路径',
			'识别结果存这里, 重启后不用重新学。默认在 /etc 下, 可持久化。');

		o = s.option(form.Value, 'persist_interval', '落盘间隔(秒)',
			'指纹有变化时会额外立即落盘; 退出时也会保存, 不会丢。');
		o.datatype = 'uinteger';

		o = s.option(form.Value, 'evidence_halflife', 'DNS 证据半衰期(秒)',
			'设备换固件、改用途之后, 旧的 DNS 行为不该永远算数。每过一个半衰期, ' +
			'一条命中记录的权重减半; 衰减到 15% 以下不再参与判定, 5% 以下从档案删除。' +
			'默认 7 天, 填 0 关闭衰减。');
		o.datatype = 'uinteger';

		o = s.option(form.Value, 'max_age', '档案保留时长(秒)',
			'超过这个时间没再见到的设备会被清除。默认 30 天。');
		o.datatype = 'uinteger';

		o = s.option(form.Flag, 'keep_unmatched', '保留未命中域名',
			'打开后每台设备最多留 50 条没有匹配规则的域名, 用来补规则库。' +
			'这等于在路由器上留一份访问记录, 默认关闭。');

		s = m.section(form.NamedSection, 'global', 'whohere', '强制 DNS (可选)');
		s.anonymous = true;

		o = s.option(form.Flag, 'force_dns', '把 LAN 的 53 端口拉回本机',
			'只能治"自己填了 8.8.8.8"的设备。治不了 DoH —— 那是 443 上的普通 HTTPS。');

		o = s.option(form.Value, 'force_dns_zone', '作用区域');
		o.depends('force_dns', '1');

		o = s.option(form.Flag, 'block_dot', '同时拦截 DoT (853)',
			'逼设备退回明文 DNS。可能导致部分设备解析变慢或失败, 谨慎开启。');

		return m.render().then(function (formEl) {
			return E('div', {}, [
				E('h2', {}, 'WhoHere'),
				E('div', { 'class': 'cbi-map-descr' },
					'融合 DHCP 指纹、mDNS/SSDP、DNS 心跳域名和 MAC OUI 四路信号识别局域网设备。' +
					'点设备名可以看到每一条判定依据。'),
				E('div', { 'class': 'cbi-section' }, [
					statsEl,
					renderProbePanel(self),
					srcEl
				]),
				E('div', { 'style': 'margin-bottom:1em' }, [
					E('button', {
						'class': 'btn cbi-button-action',
						'click': ui.createHandlerFn(self, function () {
							return callScan().then(function () {
								ui.addNotification(null,
									E('p', '已发起一轮 mDNS/SSDP 组播查询并重读租约与邻居表'),
									'info');
							});
						})
					}, '立即刷新'),
					' ',
					E('button', {
						'class': 'btn cbi-button-neutral',
						'click': ui.createHandlerFn(self, function () {
							ui.addNotification(null, E('p', '正在下载 IEEE OUI 库, 可能需要一会儿…'), 'info');
							return callUpdateOui().then(function (r) {
								ui.addNotification(null, E('p',
									(r && r.ok) ? ('OUI 库已更新, 共 ' + r.entries + ' 条')
										: ('更新失败: ' + ((r && r.error) || '未知错误'))),
									(r && r.ok) ? 'info' : 'error');
							});
						})
					}, '更新 OUI 库')
				]),
				E('div', {}, table),
				E('hr'),
				formEl
			]);
		});
	}
});
