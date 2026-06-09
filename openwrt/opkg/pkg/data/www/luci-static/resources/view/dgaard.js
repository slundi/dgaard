'use strict';
'require view';
'require rpc';
'require ui';
'require dom';

// ---------------------------------------------------------------------------
// RPC declarations
// ---------------------------------------------------------------------------
var callGetConfig = rpc.declare({
    object: 'dgaard',
    method: 'get_config',
    expect: {}
});

var callSetConfig = rpc.declare({
    object: 'dgaard',
    method: 'set_config',
    params: ['config']
});

var callRestart = rpc.declare({
    object: 'dgaard',
    method: 'restart'
});

var callStatus = rpc.declare({
    object: 'dgaard',
    method: 'status',
    expect: { running: false }
});

// ---------------------------------------------------------------------------
// Minimal UI helpers (no dependency on form/cbi for full control)
// ---------------------------------------------------------------------------

function field(id, label, inputHtml, hint) {
    return E('div', { class: 'cbi-value' }, [
        E('label', { class: 'cbi-value-title', for: id }, label),
        E('div', { class: 'cbi-value-field' }, [
            inputHtml,
            hint ? E('span', { class: 'cbi-value-description' }, hint) : ''
        ])
    ]);
}

function textInput(id, val, placeholder) {
    return E('input', {
        type: 'text',
        id: id,
        name: id,
        class: 'cbi-input-text',
        value: val || '',
        placeholder: placeholder || ''
    });
}

function numberInput(id, val, min, max) {
    return E('input', {
        type: 'number',
        id: id,
        name: id,
        class: 'cbi-input-text',
        value: val || '',
        min: min != null ? String(min) : null,
        max: max != null ? String(max) : null,
        style: 'width:120px'
    });
}

function checkbox(id, val) {
    return E('input', {
        type: 'checkbox',
        id: id,
        name: id,
        class: 'cbi-input-checkbox',
        checked: (val === 'true' || val === true) ? '' : null
    });
}

function selectInput(id, val, options) {
    return E('select', { id: id, name: id, class: 'cbi-input-select' },
        options.map(function(o) {
            return E('option', { value: o, selected: val === o ? '' : null }, o);
        })
    );
}

// Textarea for newline-separated lists
function listArea(id, val, rows, placeholder) {
    var text = Array.isArray(val) ? val.join('\n') : (val || '').replace(/\\n/g, '\n');
    return E('textarea', {
        id: id,
        name: id,
        class: 'cbi-input-textarea',
        rows: rows || 4,
        style: 'width:100%; font-family:monospace; font-size:0.85em',
        placeholder: placeholder || ''
    }, [ text ]);
}

function section(title, content) {
    return E('div', { class: 'cbi-section' }, [
        E('h3', {}, title),
        E('div', { class: 'cbi-section-node' }, content)
    ]);
}

// Read a field value back (checkbox → 'true'/'false', textarea → \n-joined)
function readField(id) {
    var el = document.getElementById(id);
    if (!el) return '';
    if (el.type === 'checkbox') return el.checked ? 'true' : 'false';
    if (el.tagName === 'TEXTAREA') return el.value.split('\n').filter(function(l){ return l.trim(); }).join('\\n');
    return el.value;
}

// ---------------------------------------------------------------------------
// Main view
// ---------------------------------------------------------------------------
return view.extend({

    load: function() {
        return Promise.all([callGetConfig(), callStatus()]);
    },

    render: function(data) {
        var cfg     = data[0] || {};
        var running = data[1];

        // --- Status bar ---
        var statusBadge = E('span', {
            style: 'padding:2px 10px; border-radius:4px; font-weight:bold; color:#fff; background:' +
                   (running ? '#28a745' : '#dc3545')
        }, running ? _('Running') : _('Stopped'));

        var restartBtn = E('button', {
            class: 'cbi-button cbi-button-action',
            style: 'margin-left:12px',
            click: function() {
                callRestart().then(function() {
                    ui.addNotification(null, E('p', _('Dgaard restarted.')), 'info');
                });
            }
        }, _('Restart'));

        var statusBar = E('div', { style: 'margin-bottom:16px; display:flex; align-items:center; gap:8px' }, [
            E('strong', {}, _('Status: ')),
            statusBadge,
            restartBtn
        ]);

        // --- Save button at top + bottom ---
        var saveBtn = function() {
            return E('button', {
                class: 'cbi-button cbi-button-save',
                click: function() {
                    // Collect all fields
                    var allKeys = [
                        'server_listen_addr','server_allowed_networks_list','server_stats_socket_path',
                        'server_block_idn','server_pipeline_list',
                        'server_runtime_worker_threads','server_runtime_stack_size','server_runtime_max_blocking_threads',
                        'sec_struct_max_subdomain_depth','sec_struct_max_domain_length','sec_struct_force_lowercase_ascii',
                        'sec_struct_max_txt_record_length','sec_struct_max_answers_per_query',
                        'sec_lex_enabled','sec_lex_banned_keywords_list','sec_lex_strict_keyword_matching',
                        'sec_intel_enabled','sec_intel_entropy_threshold','sec_intel_entropy_fast',
                        'sec_intel_min_word_length','sec_intel_consonant_ratio_threshold','sec_intel_max_consonant_sequence',
                        'sec_intel_use_ngram_model','sec_intel_ngram_use_embedded','sec_intel_ngram_embedded_languages_list',
                        'sec_intel_ngram_probability_threshold',
                        'sec_idn_mode','sec_idn_allowed_scripts_list',
                        'sec_behavior_nxdomain_threshold','sec_behavior_nxdomain_window',
                        'sec_behavior_max_subdomains_per_minute','sec_behavior_max_label_length',
                        'sec_inbound_enabled','sec_inbound_max_txt_entropy','sec_inbound_unmask_cname_cloaking',
                        'sec_inbound_block_private_ip','sec_inbound_forbidden_qtypes_list',
                        'sec_rebinding_enabled',
                        'sec_low_ttl_enabled','sec_low_ttl_threshold_secs',
                        'sec_asn_enabled',
                        'sec_scoring_blocking_threshold','sec_scoring_highly_suspicious_threshold',
                        'sec_scoring_suspicious_threshold','sec_scoring_log_suspicious',
                        'upstream_servers_list','upstream_timeout_ms',
                        'tld_exclude_list','tld_suspicious_list',
                        'sources_nrd_list_path','sources_blacklists_list','sources_whitelists_list',
                        'sources_update_interval_hours','sources_retry_delay_mins',
                        'sources_host_index_path','sources_browser_rules_path',
                        'abp_extract_domain_only','abp_update_interval',
                        'cache_enabled','cache_max_entries','cache_ttl_override',
                        'memory_cache_enabled','memory_cache_size','memory_use_bloom_filter','memory_expected_total_domains',
                        'nxdomain_hunting_enabled','nxdomain_hunting_threshold','nxdomain_hunting_window_seconds','nxdomain_hunting_action',
                        'tunneling_enabled','tunneling_max_subdomains_per_minute','tunneling_max_label_length'
                    ];
                    var payload = {};
                    allKeys.forEach(function(k) { payload[k] = readField(k); });
                    callSetConfig(payload).then(function(res) {
                        if (res && res.result === 'ok') {
                            ui.addNotification(null, E('p', _('Configuration saved. Restart dgaard to apply.')), 'info');
                        } else {
                            ui.addNotification(null, E('p', _('Save failed.')), 'error');
                        }
                    });
                }
            }, _('Save configuration'));
        };

        // ===================================================================
        // Build sections
        // ===================================================================

        var serverSection = section(_('Server'), [
            field('server_listen_addr', _('Listen address'),
                textInput('server_listen_addr', cfg.server_listen_addr, '192.168.1.1:53'),
                _('IP:port the proxy listens on (usually port 53)')),
            field('server_allowed_networks_list', _('Allowed networks (ACL)'),
                listArea('server_allowed_networks_list', cfg.server_allowed_networks_list, 3, '127.0.0.1/32\n192.168.1.0/24'),
                _('One CIDR per line — clients allowed to use this proxy')),
            field('server_stats_socket_path', _('Stats socket path'),
                textInput('server_stats_socket_path', cfg.server_stats_socket_path, '/var/run/dgaard/stats.sock')),
            field('server_block_idn', _('Block IDN (Punycode) domains'),
                checkbox('server_block_idn', cfg.server_block_idn)),
            field('server_pipeline_list', _('Pipeline stages'),
                listArea('server_pipeline_list', cfg.server_pipeline_list, 7,
                    'Whitelist\nHotCache\nStaticBlock\nSuffixMatch\nHeuristics\nUpstream'),
                _('One stage per line, in execution order')),
        ]);

        var runtimeSection = section(_('Runtime'), [
            field('server_runtime_worker_threads', _('Worker threads'),
                numberInput('server_runtime_worker_threads', cfg.server_runtime_worker_threads, 1, 8),
                _('"auto" uses all CPU cores — on OpenWrt set 1 or 2')),
            field('server_runtime_stack_size', _('Stack size per thread (bytes)'),
                numberInput('server_runtime_stack_size', cfg.server_runtime_stack_size, 524288),
                _('2 097 152 = 2 MB — reduce on memory-constrained devices')),
            field('server_runtime_max_blocking_threads', _('Max blocking threads'),
                numberInput('server_runtime_max_blocking_threads', cfg.server_runtime_max_blocking_threads, 1)),
        ]);

        var structSection = section(_('Security — Structure'), [
            field('sec_struct_max_subdomain_depth', _('Max subdomain depth'),
                numberInput('sec_struct_max_subdomain_depth', cfg.sec_struct_max_subdomain_depth, 1, 20),
                _('Dots in FQDN — tunneling often uses > 5')),
            field('sec_struct_max_domain_length', _('Max domain length'),
                numberInput('sec_struct_max_domain_length', cfg.sec_struct_max_domain_length, 1, 253),
                _('RFC max is 253')),
            field('sec_struct_force_lowercase_ascii', _('Force lowercase ASCII'),
                checkbox('sec_struct_force_lowercase_ascii', cfg.sec_struct_force_lowercase_ascii)),
            field('sec_struct_max_txt_record_length', _('Max TXT record length (bytes)'),
                numberInput('sec_struct_max_txt_record_length', cfg.sec_struct_max_txt_record_length, 1, 255)),
            field('sec_struct_max_answers_per_query', _('Max answers per query'),
                numberInput('sec_struct_max_answers_per_query', cfg.sec_struct_max_answers_per_query, 1)),
        ]);

        var lexicalSection = section(_('Security — Lexical / Parental control'), [
            field('sec_lex_enabled', _('Enabled'),
                checkbox('sec_lex_enabled', cfg.sec_lex_enabled)),
            field('sec_lex_banned_keywords_list', _('Banned keywords'),
                listArea('sec_lex_banned_keywords_list', cfg.sec_lex_banned_keywords_list, 4, 'casino\nporno\nsex'),
                _('One keyword per line — matched against labels in the domain')),
            field('sec_lex_strict_keyword_matching', _('Strict keyword matching (full label only)'),
                checkbox('sec_lex_strict_keyword_matching', cfg.sec_lex_strict_keyword_matching),
                _('Unchecked = substring match (more aggressive)')),
        ]);

        var intelSection = section(_('Security — Intelligence (DGA / Entropy)'), [
            field('sec_intel_enabled', _('Enabled'),
                checkbox('sec_intel_enabled', cfg.sec_intel_enabled)),
            field('sec_intel_entropy_threshold', _('Entropy threshold'),
                textInput('sec_intel_entropy_threshold', cfg.sec_intel_entropy_threshold, '4.0'),
                _('3.5–4.5 typical; higher = more lenient')),
            field('sec_intel_entropy_fast', _('Fast ASCII entropy (zero-alloc)'),
                checkbox('sec_intel_entropy_fast', cfg.sec_intel_entropy_fast),
                _('Recommended on OpenWrt')),
            field('sec_intel_min_word_length', _('Min word length'),
                numberInput('sec_intel_min_word_length', cfg.sec_intel_min_word_length, 1)),
            field('sec_intel_consonant_ratio_threshold', _('Consonant ratio threshold'),
                textInput('sec_intel_consonant_ratio_threshold', cfg.sec_intel_consonant_ratio_threshold, '0.6')),
            field('sec_intel_max_consonant_sequence', _('Max consecutive consonants'),
                numberInput('sec_intel_max_consonant_sequence', cfg.sec_intel_max_consonant_sequence, 1)),
            E('hr'),
            field('sec_intel_use_ngram_model', _('Enable N-Gram model'),
                checkbox('sec_intel_use_ngram_model', cfg.sec_intel_use_ngram_model)),
            field('sec_intel_ngram_use_embedded', _('Use embedded Markov matrices (~2.7 KB/lang)'),
                checkbox('sec_intel_ngram_use_embedded', cfg.sec_intel_ngram_use_embedded),
                _('Unchecked = load external .bin files — higher accuracy, more RAM')),
            field('sec_intel_ngram_embedded_languages_list', _('Embedded languages'),
                listArea('sec_intel_ngram_embedded_languages_list', cfg.sec_intel_ngram_embedded_languages_list, 3,
                    'english\nfrench'),
                _('Supported: english, french, german, spanish, italian')),
            field('sec_intel_ngram_probability_threshold', _('N-Gram probability threshold'),
                textInput('sec_intel_ngram_probability_threshold', cfg.sec_intel_ngram_probability_threshold, '-4.0'),
                _('-6.0 (strict) to -3.0 (lenient)')),
        ]);

        var idnSection = section(_('Security — IDN'), [
            field('sec_idn_mode', _('IDN filtering mode'),
                selectInput('sec_idn_mode', cfg.sec_idn_mode, ['Off', 'Strict', 'Smart']),
                _('force_lowercase_ascii must be false to use Smart/Strict')),
            field('sec_idn_allowed_scripts_list', _('Allowed scripts'),
                listArea('sec_idn_allowed_scripts_list', cfg.sec_idn_allowed_scripts_list, 2, 'Latin\nWesternEuropean')),
        ]);

        var inboundSection = section(_('Security — Inbound (DPI Lite)'), [
            field('sec_inbound_enabled', _('Enabled'),
                checkbox('sec_inbound_enabled', cfg.sec_inbound_enabled)),
            field('sec_inbound_max_txt_entropy', _('Max TXT record entropy'),
                textInput('sec_inbound_max_txt_entropy', cfg.sec_inbound_max_txt_entropy, '4.5')),
            field('sec_inbound_unmask_cname_cloaking', _('Unmask CNAME cloaking'),
                checkbox('sec_inbound_unmask_cname_cloaking', cfg.sec_inbound_unmask_cname_cloaking)),
            field('sec_inbound_block_private_ip', _('Block DNS rebinding (public → private IP)'),
                checkbox('sec_inbound_block_private_ip', cfg.sec_inbound_block_private_ip)),
            field('sec_inbound_forbidden_qtypes_list', _('Forbidden query types'),
                listArea('sec_inbound_forbidden_qtypes_list', cfg.sec_inbound_forbidden_qtypes_list, 2, 'NULL\nANY'),
                _('One qtype per line — e.g. NULL, ANY, HINFO')),
        ]);

        var scoringSection = section(_('Security — Scoring thresholds'), [
            field('sec_scoring_blocking_threshold', _('Blocking threshold'),
                numberInput('sec_scoring_blocking_threshold', cfg.sec_scoring_blocking_threshold, 1),
                _('Score ≥ this → domain blocked. Default: 10')),
            field('sec_scoring_highly_suspicious_threshold', _('Highly suspicious threshold'),
                numberInput('sec_scoring_highly_suspicious_threshold', cfg.sec_scoring_highly_suspicious_threshold, 1),
                _('Score ≥ this → HighlySuspicious event. Default: 7')),
            field('sec_scoring_suspicious_threshold', _('Suspicious threshold'),
                numberInput('sec_scoring_suspicious_threshold', cfg.sec_scoring_suspicious_threshold, 1),
                _('Score ≥ this → Suspicious event (if log_suspicious). Default: 4')),
            field('sec_scoring_log_suspicious', _('Log suspicious events'),
                checkbox('sec_scoring_log_suspicious', cfg.sec_scoring_log_suspicious)),
            field('sec_rebinding_enabled', _('DNS rebinding shield'),
                checkbox('sec_rebinding_enabled', cfg.sec_rebinding_enabled)),
            field('sec_low_ttl_enabled', _('Low-TTL suspicion scoring'),
                checkbox('sec_low_ttl_enabled', cfg.sec_low_ttl_enabled)),
            field('sec_low_ttl_threshold_secs', _('Low-TTL threshold (seconds)'),
                numberInput('sec_low_ttl_threshold_secs', cfg.sec_low_ttl_threshold_secs, 1),
                _('Responses with TTL below this add suspicion points')),
            field('sec_asn_enabled', _('ASN filter (CIDR block list)'),
                checkbox('sec_asn_enabled', cfg.sec_asn_enabled),
                _('Requires blocked_ranges in config.toml — edit manually for now')),
        ]);

        var behaviorSection = section(_('Behavior monitoring'), [
            field('sec_behavior_nxdomain_threshold', _('NXDOMAIN threshold'),
                numberInput('sec_behavior_nxdomain_threshold', cfg.sec_behavior_nxdomain_threshold, 1)),
            field('sec_behavior_nxdomain_window', _('NXDOMAIN window (seconds)'),
                numberInput('sec_behavior_nxdomain_window', cfg.sec_behavior_nxdomain_window, 1)),
            field('sec_behavior_max_subdomains_per_minute', _('Max subdomains/min'),
                numberInput('sec_behavior_max_subdomains_per_minute', cfg.sec_behavior_max_subdomains_per_minute, 1)),
            field('sec_behavior_max_label_length', _('Max label length'),
                numberInput('sec_behavior_max_label_length', cfg.sec_behavior_max_label_length, 1)),
            E('hr'),
            field('nxdomain_hunting_enabled', _('NXDOMAIN hunting enabled'),
                checkbox('nxdomain_hunting_enabled', cfg.nxdomain_hunting_enabled)),
            field('nxdomain_hunting_threshold', _('Hunting threshold'),
                numberInput('nxdomain_hunting_threshold', cfg.nxdomain_hunting_threshold, 1)),
            field('nxdomain_hunting_window_seconds', _('Hunting window (seconds)'),
                numberInput('nxdomain_hunting_window_seconds', cfg.nxdomain_hunting_window_seconds, 1)),
            field('nxdomain_hunting_action', _('Hunting action'),
                selectInput('nxdomain_hunting_action', cfg.nxdomain_hunting_action, ['log', 'block_client'])),
            E('hr'),
            field('tunneling_enabled', _('Tunneling detection enabled'),
                checkbox('tunneling_enabled', cfg.tunneling_enabled)),
            field('tunneling_max_subdomains_per_minute', _('Max subdomains/min (tunneling)'),
                numberInput('tunneling_max_subdomains_per_minute', cfg.tunneling_max_subdomains_per_minute, 1)),
            field('tunneling_max_label_length', _('Max label length (tunneling)'),
                numberInput('tunneling_max_label_length', cfg.tunneling_max_label_length, 1)),
        ]);

        var upstreamSection = section(_('Upstream DNS'), [
            field('upstream_servers_list', _('Upstream servers'),
                listArea('upstream_servers_list', cfg.upstream_servers_list, 3, '1.1.1.1:53\n9.9.9.9:53'),
                _('One IP:port per line')),
            field('upstream_timeout_ms', _('Timeout (ms)'),
                numberInput('upstream_timeout_ms', cfg.upstream_timeout_ms, 100, 10000)),
        ]);

        var tldSection = section(_('TLD Filtering'), [
            field('tld_exclude_list', _('Excluded TLDs'),
                listArea('tld_exclude_list', cfg.tld_exclude_list, 5, '.top\n.xyz\n.bid'),
                _('Domains with these TLDs are never resolved. One TLD per line.')),
            field('tld_suspicious_list', _('Suspicious TLDs (conditional block)'),
                listArea('tld_suspicious_list', cfg.tld_suspicious_list, 8, '.biz\n.ru\n.cn'),
                _('Adds suspicion score when combined with a banned keyword. One TLD per line.')),
        ]);

        var sourcesSection = section(_('Sources — Blocklists & Whitelists'), [
            field('sources_nrd_list_path', _('NRD list path'),
                textInput('sources_nrd_list_path', cfg.sources_nrd_list_path, '/tmp/nrd_daily.txt'),
                _('Newly Registered Domains — updated via cron')),
            field('sources_blacklists_list', _('Blacklists (URLs or paths)'),
                listArea('sources_blacklists_list', cfg.sources_blacklists_list, 8,
                    'https://pgl.yoyo.org/as/serverlist.php?...\n/etc/dgaard/lists/custom.txt'),
                _('One URL or file path per line — supports ABP format')),
            field('sources_whitelists_list', _('Whitelists (URLs or paths)'),
                listArea('sources_whitelists_list', cfg.sources_whitelists_list, 4,
                    'https://raw.githubusercontent.com/.../whitelist.txt')),
            field('sources_update_interval_hours', _('Update interval (hours)'),
                numberInput('sources_update_interval_hours', cfg.sources_update_interval_hours, 1)),
            field('sources_retry_delay_mins', _('Retry delay on failure (minutes)'),
                numberInput('sources_retry_delay_mins', cfg.sources_retry_delay_mins, 1)),
            field('sources_host_index_path', _('Host index path (binary, "" to disable)'),
                textInput('sources_host_index_path', cfg.sources_host_index_path, '/var/dgaard/host_mapping.bin')),
            field('sources_browser_rules_path', _('Browser rules path (ABP cosmetic, "" to disable)'),
                textInput('sources_browser_rules_path', cfg.sources_browser_rules_path, '/var/dgaard/browser_rules.txt')),
            E('hr'),
            field('abp_extract_domain_only', _('ABP: extract domain rules only'),
                checkbox('abp_extract_domain_only', cfg.abp_extract_domain_only),
                _('Cosmetic/scriptlet rules are ignored by the DNS filter')),
            field('abp_update_interval', _('ABP update interval (hours)'),
                numberInput('abp_update_interval', cfg.abp_update_interval, 1)),
        ]);

        var cacheSection = section(_('Cache & Memory'), [
            field('cache_enabled', _('DNS cache enabled'),
                checkbox('cache_enabled', cfg.cache_enabled)),
            field('cache_max_entries', _('Max cache entries'),
                numberInput('cache_max_entries', cfg.cache_max_entries, 100)),
            field('cache_ttl_override', _('TTL override (0 = use DNS record TTL)'),
                numberInput('cache_ttl_override', cfg.cache_ttl_override, 0)),
            E('hr'),
            field('memory_cache_enabled', _('LRU hot cache enabled'),
                checkbox('memory_cache_enabled', cfg.memory_cache_enabled)),
            field('memory_cache_size', _('LRU cache size (entries)'),
                numberInput('memory_cache_size', cfg.memory_cache_size, 100)),
            field('memory_use_bloom_filter', _('Use Bloom filter for large lists'),
                checkbox('memory_use_bloom_filter', cfg.memory_use_bloom_filter),
                _('Recommended on OpenWrt — reduces RAM for large blocklists')),
            field('memory_expected_total_domains', _('Expected total domains (Bloom sizing)'),
                numberInput('memory_expected_total_domains', cfg.memory_expected_total_domains, 10000)),
        ]);

        // ===================================================================
        // Assemble page
        // ===================================================================
        return E('div', { class: 'cbi-map' }, [
            E('h2', {}, _('Dgaard DNS Proxy')),
            statusBar,
            saveBtn(),
            serverSection,
            runtimeSection,
            structSection,
            lexicalSection,
            intelSection,
            idnSection,
            inboundSection,
            scoringSection,
            behaviorSection,
            upstreamSection,
            tldSection,
            sourcesSection,
            cacheSection,
            E('div', { style: 'margin-top:16px' }, saveBtn()),
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
