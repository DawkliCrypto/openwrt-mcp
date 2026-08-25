'use strict';
'require rpc';
'require view';

var callStatus = rpc.declare({
	object: 'luci.openwrt_mcp',
	method: 'status',
	expect: {}
});

function text(value) {
	return value === undefined || value === null || value === '' ? '-' : String(value);
}

function cell(value) {
	return E('div', { 'class': 'td' }, text(value));
}

function table(title, headers, rows) {
	var children = [E('h3', {}, title)];
	if (!rows.length) {
		children.push(E('p', { 'class': 'cbi-section-descr' }, _('None')));
		return E('div', { 'class': 'cbi-section' }, children);
	}

	var body = [E('div', { 'class': 'tr table-titles' }, headers.map(function(header) {
		return E('div', { 'class': 'th' }, header);
	}))];
	rows.forEach(function(row) {
		body.push(E('div', { 'class': 'tr' }, row.map(cell)));
	});
	children.push(E('div', { 'class': 'table' }, body));
	return E('div', { 'class': 'cbi-section' }, children);
}

return view.extend({
	load: function() {
		return L.resolveDefault(callStatus(), null);
	},

	render: function(status) {
		if (!status)
			return E('div', { 'class': 'alert-message warning' },
				_('Unable to load MCP Server status.'));

		var clients = (status.clients || []).map(function(client) {
			return [client.name, client.policies];
		});
		var policies = (status.policies || []).map(function(policy) {
			return [policy.client, (policy.tools || []).join(', '),
				(policy.scopes || []).join(' '), policy.max_per_min,
				policy.expired ? _('Expired') : text(policy.expires || _('Never'))];
		});
		var audit = (status.audit || []).slice().reverse().map(function(entry) {
			return [entry.time, entry.outcome, entry.client, entry.tool,
				entry.scope, entry.summary || entry.error];
		});

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('MCP Server')),
			E('div', { 'class': 'cbi-section' }, [
				E('div', { 'class': 'table' }, [
					E('div', { 'class': 'tr table-titles' }, [
						E('div', { 'class': 'th' }, _('State')),
						E('div', { 'class': 'th' }, _('Version')),
						E('div', { 'class': 'th' }, _('Listen address')),
						E('div', { 'class': 'th' }, _('Clients')),
						E('div', { 'class': 'th' }, _('Policies'))
					]),
					E('div', { 'class': 'tr' }, [
						cell(status.running ? _('Running') : _('Stopped')),
						cell(status.version), cell(status.listen),
						cell((status.counts || {}).clients || 0),
						cell((status.counts || {}).policies || 0)
					])
				])
			]),
			table(_('Paired clients'), [_('Client'), _('Policies')], clients),
			table(_('Standing policies'), [_('Client'), _('Tools'), _('Scopes'),
				_('Rate / min'), _('Expires')], policies),
			table(_('Recent audit'), [_('Time'), _('Outcome'), _('Client'), _('Tool'),
				_('Scope'), _('Summary')], audit)
		]);
	}
});
