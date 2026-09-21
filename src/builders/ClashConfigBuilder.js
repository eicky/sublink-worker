import yaml from 'js-yaml';
import { CLASH_CONFIG, generateRules, generateClashRuleSets, getOutbounds, PREDEFINED_RULE_SETS, DIRECT_DEFAULT_RULES } from '../config/index.js';
import { BaseConfigBuilder } from './BaseConfigBuilder.js';
import { deepCopy, groupProxiesByCountry, buildCountryNameFilter } from '../utils.js';
import { addProxyWithDedup } from './helpers/proxyHelpers.js';
import { buildSelectorMembers, buildNodeSelectMembers, buildCustomRuleMembers, uniqueNames } from './helpers/groupBuilder.js';
import { emitClashRules, sanitizeClashProxyGroups } from './helpers/clashConfigUtils.js';
import { normalizeGroupName, findGroupIndexByName } from './helpers/groupNameUtils.js';
import { InvalidConfigError } from '../services/errors.js';
import { buildClashProxy } from './helpers/clashProxy.js';

/**
 * Check if the client supports MRS (Meta Rule Set) format
 * MRS is a binary format supported by Clash Meta/mihomo
 * Legacy Clash clients need YAML format instead
 * @param {string} userAgent - Client User-Agent string
 * @returns {boolean} - True if client supports MRS format
 */
function supportsMrsFormat(userAgent) {
    if (!userAgent) return true; // Default to mrs for unknown clients
    const ua = userAgent.toLowerCase();
    
    // Clients confirmed to support MRS format (Clash Meta/mihomo based)
    if (ua.includes('mihomo') || 
        ua.includes('meta') ||           // clash.meta, clashx meta, meta-for-android, etc.
        ua.includes('clash-verge') ||
        ua.includes('stash') ||
        ua.includes('verge')) {
        return true;
    }
    
    // Legacy clients that don't support MRS format
    if (ua.includes('merlin') ||
        ua.includes('clashforwindows') ||
        ua.includes('clashforandroid') ||
        ua.includes('clash/')) {         // 老版本Clash核心 (Clash/v1.x.x)
        return false;
    }
    
    // Default: use mrs for unknown clients (most modern clients support it)
    return true;
}

export class ClashConfigBuilder extends BaseConfigBuilder {
    outputFormat = 'yamlConfig';
    constructor(inputString, selectedRules, customRules, baseConfig, lang, userAgent, groupByCountry = false, enableClashUI = false, externalController, externalUiDownloadUrl, includeAutoSelect = true, skipCertVerify = false) {
        if (!baseConfig) {
            baseConfig = CLASH_CONFIG;
        }
        super(inputString, baseConfig, lang, userAgent, groupByCountry, includeAutoSelect);
        this.selectedRules = selectedRules;
        this.customRules = customRules;
        this.countryGroupNames = [];
        this.manualGroupName = null;
        this.enableClashUI = enableClashUI;
        this.externalController = externalController;
        this.externalUiDownloadUrl = externalUiDownloadUrl;
        this.skipCertVerify = skipCertVerify;
    }

    /**
     * Check if subscription format is compatible for use as Clash proxy-provider
     * @param {'clash'|'singbox'|'unknown'} format - Detected subscription format
     * @returns {boolean} - True if format is Clash YAML
     */
    isCompatibleProviderFormat(format) {
        return format === 'clash';
    }

    /**
     * Generate proxy-providers configuration from collected URLs
     * @returns {object} - proxy-providers object
     */
    generateProxyProviders() {
        const providers = {};
        const existingProviders = this.getExistingProviderNames();
        this.getAutoProviderDescriptors(existingProviders).forEach(({ name, url }) => {
            providers[name] = {
                type: 'http',
                url: url,
                path: `./proxy_providers/${name}.yaml`,
                interval: 3600,
                'health-check': {
                    enable: true,
                    url: 'https://www.gstatic.com/generate_204',
                    interval: 300,
                    timeout: 5000,
                    lazy: true
                }
            };
        });
        return providers;
    }

    /**
     * Get list of provider names
     * @returns {string[]} - Array of provider names
     */
    getProviderNames() {
        return this.getAutoProviderDescriptors(this.getExistingProviderNames()).map(provider => provider.name);
    }

    getExistingProviderNames() {
        return this.config?.['proxy-providers'] && typeof this.config['proxy-providers'] === 'object'
            ? Object.keys(this.config['proxy-providers'])
            : [];
    }

    /**
     * Get all provider names (user-defined + auto-generated)
     * @returns {string[]} - Array of provider names
     */
    getAllProviderNames() {
        const existingProviders = this.getExistingProviderNames();
        const autoProviders = this.getProviderNames();
        return [...new Set([...existingProviders, ...autoProviders])];
    }

    getProxies() {
        return this.config.proxies || [];
    }

    getProxyName(proxy) {
        return proxy.name;
    }

    convertProxy(proxy) {
        return buildClashProxy(proxy, this.skipCertVerify);
    }

    addProxyToConfig(proxy) {
        this.config.proxies = this.config.proxies || [];
        addProxyWithDedup(this.config.proxies, proxy, {
            getName: (item) => item?.name,
            setName: (item, name) => {
                if (item) item.name = name;
            },
            isSame: (a = {}, b = {}) => {
                const { name: _name, ...restOfProxy } = b;
                const { name: __name, ...restOfExisting } = a;
                return JSON.stringify(restOfProxy) === JSON.stringify(restOfExisting);
            }
        });
    }

    hasProxyGroup(name) {
        const target = normalizeGroupName(name);
        return (this.config['proxy-groups'] || []).some(group => group && normalizeGroupName(group.name) === target);
    }

    hasSelectableSources(proxyList = []) {
        return uniqueNames(proxyList).length > 0 || this.getAllProviderNames().length > 0;
    }

    shouldIncludeAutoSelectGroup(proxyList = []) {
        return this.includeAutoSelect && this.hasSelectableSources(proxyList);
    }

    addAutoSelectGroup(proxyList) {
        if (!this.includeAutoSelect) return;
        this.config['proxy-groups'] = this.config['proxy-groups'] || [];
        const autoName = this.t('outboundNames.Auto Select');
        if (this.hasProxyGroup(autoName)) return;
        const providerNames = this.getAllProviderNames();
        if (uniqueNames(proxyList).length === 0 && providerNames.length === 0) return;

        const group = {
            name: autoName,
            type: 'url-test',
            proxies: deepCopy(uniqueNames(proxyList)),
            url: 'https://www.gstatic.com/generate_204',
            interval: 300,
            lazy: false
        };

        if (providerNames.length > 0) {
            group.use = providerNames;
        }

        this.config['proxy-groups'].push(group);
    }

    addNodeSelectGroup(proxyList) {
        this.config['proxy-groups'] = this.config['proxy-groups'] || [];
        const nodeName = this.t('outboundNames.Node Select');
        if (this.hasProxyGroup(nodeName)) return;
        const list = buildNodeSelectMembers({
            proxyList,
            translator: this.t,
            groupByCountry: this.groupByCountry,
            manualGroupName: this.manualGroupName,
            countryGroupNames: this.countryGroupNames,
            includeAutoSelect: this.shouldIncludeAutoSelectGroup(proxyList)
        });

        const group = {
            type: "select",
            name: nodeName,
            proxies: list
        };

        // Add 'use' field if we have proxy-providers
        const providerNames = this.getAllProviderNames();
        if (providerNames.length > 0) {
            group.use = providerNames;
        }

        this.config['proxy-groups'].unshift(group);
    }

    buildSelectGroupMembers(proxyList = []) {
        return buildSelectorMembers({
            proxyList,
            translator: this.t,
            groupByCountry: this.groupByCountry,
            manualGroupName: this.manualGroupName,
            countryGroupNames: this.countryGroupNames,
            includeAutoSelect: this.shouldIncludeAutoSelectGroup(proxyList)
        });
    }

    addOutboundGroups(outbounds, proxyList) {
        outbounds.forEach(outbound => {
            if (outbound !== this.t('outboundNames.Node Select')) {
                const name = this.t(`outboundNames.${outbound}`);
                if (!this.hasProxyGroup(name)) {
                    let proxies = this.buildSelectGroupMembers(proxyList);
                    // For rules that should default to DIRECT, move DIRECT to the front
                    if (DIRECT_DEFAULT_RULES.has(outbound)) {
                        proxies = ['DIRECT', ...proxies.filter(p => p !== 'DIRECT')];
                    }
                    const group = {
                        type: "select",
                        name,
                        proxies
                    };
                    // Add 'use' field if we have proxy-providers
                    const providerNames = this.getAllProviderNames();
                    if (providerNames.length > 0) {
                        group.use = providerNames;
                    }
                    this.config['proxy-groups'].push(group);
                }
            }
        });
    }

    addCustomRuleGroups(proxyList) {
        if (Array.isArray(this.customRules)) {
            this.customRules.forEach(rule => {
                const name = this.t(`outboundNames.${rule.name}`);
                if (!this.hasProxyGroup(name)) {
                    const proxies = buildCustomRuleMembers({
                        proxyList,
                        translator: this.t,
                        manualGroupName: this.manualGroupName,
                        includeAutoSelect: this.shouldIncludeAutoSelectGroup(proxyList)
                    });
                    const group = {
                        type: "select",
                        name,
                        proxies
                    };
                    // Add 'use' field if we have proxy-providers
                    const providerNames = this.getAllProviderNames();
                    if (providerNames.length > 0) {
                        group.use = providerNames;
                    }
                    this.config['proxy-groups'].push(group);
                }
            });
        }
    }

    addFallBackGroup(proxyList) {
        const name = this.t('outboundNames.Fall Back');
        if (this.hasProxyGroup(name)) return;
        const proxies = this.buildSelectGroupMembers(proxyList);
        const group = {
            type: "select",
            name,
            proxies
        };
        // Add 'use' field if we have proxy-providers
        const providerNames = this.getAllProviderNames();
        if (providerNames.length > 0) {
            group.use = providerNames;
        }
        this.config['proxy-groups'].push(group);
    }

    addCountryGroups() {
        const proxies = this.getProxies();
        const countryGroups = groupProxiesByCountry(proxies, {
            getName: proxy => this.getProxyName(proxy)
        });

        // Provider mode leaves no inline proxies, but mihomo can filter provider
        // members per group (`use` + `filter`), so enumerate countries from the
        // names collected at fetch time and reference the providers instead.
        const providerNames = this.getAllProviderNames();
        if (providerNames.length > 0 && this.providerNodeNames.length > 0) {
            const providerCountryGroups = groupProxiesByCountry(this.providerNodeNames, {
                getName: name => name
            });
            Object.keys(providerCountryGroups).forEach(country => {
                if (!countryGroups[country]) {
                    countryGroups[country] = { ...providerCountryGroups[country], proxies: [] };
                }
            });
        }

        const existingNames = new Set((this.config['proxy-groups'] || []).map(g => normalizeGroupName(g?.name)).filter(Boolean));

        const manualProxyNames = proxies.map(p => p?.name).filter(Boolean);
        const manualGroupName = manualProxyNames.length > 0 ? this.t('outboundNames.Manual Switch') : null;
        if (manualGroupName) {
            const manualNorm = normalizeGroupName(manualGroupName);
            if (!existingNames.has(manualNorm)) {
                const group = {
                    name: manualGroupName,
                    type: 'select',
                    proxies: manualProxyNames
                };
                // Add 'use' field if we have proxy-providers
                const providerNames = this.getAllProviderNames();
                if (providerNames.length > 0) {
                    group.use = providerNames;
                }
                this.config['proxy-groups'].push(group);
                existingNames.add(manualNorm);
            }
        }

        const countries = Object.keys(countryGroups).sort((a, b) => a.localeCompare(b));
        const countryGroupNames = [];

        countries.forEach(country => {
            const { emoji, name, aliases, proxies } = countryGroups[country];
            const groupName = `${emoji} ${name}`;
            const norm = normalizeGroupName(groupName);
            if (!existingNames.has(norm)) {
                const group = {
                    name: groupName,
                    type: 'url-test',
                    proxies: proxies,
                    url: 'https://www.gstatic.com/generate_204',
                    interval: 300,
                    lazy: false
                };
                // Add 'use' field if we have proxy-providers, narrowed to this
                // country so provider members don't leak into every group
                if (providerNames.length > 0) {
                    group.use = providerNames;
                    const filter = buildCountryNameFilter({ emoji, aliases });
                    if (filter) {
                        group.filter = filter;
                    }
                }
                this.config['proxy-groups'].push(group);
                existingNames.add(norm);
            }
            countryGroupNames.push(groupName);
        });

        const nodeSelectGroup = this.config['proxy-groups'].find(g => g && g.name === this.t('outboundNames.Node Select'));
        if (nodeSelectGroup && Array.isArray(nodeSelectGroup.proxies)) {
            const rebuilt = buildNodeSelectMembers({
                proxyList: [],
                translator: this.t,
                groupByCountry: true,
                manualGroupName,
                countryGroupNames,
                includeAutoSelect: this.shouldIncludeAutoSelectGroup(this.getProxyList())
            });
            nodeSelectGroup.proxies = rebuilt;
        }
        this.countryGroupNames = countryGroupNames;
        this.manualGroupName = manualGroupName;
    }

    /**
     * Merge user-defined proxy groups with system-generated ones
     * Handles same-name groups by merging proxies/use fields and preserving user settings
     * @param {Array} userGroups - User-defined proxy groups from input config
     */
    mergeUserProxyGroups(userGroups) {
        if (!Array.isArray(userGroups)) return;

        const proxyList = this.getProxyList();
        const allProviderNames = new Set(this.getAllProviderNames());

        // Build valid reference set (proxies, groups, special names)
        const groupNames = new Set(
            (this.config['proxy-groups'] || [])
                .map(g => normalizeGroupName(g?.name))
                .filter(Boolean)
        );
        const validRefs = new Set(['DIRECT', 'REJECT']);
        proxyList.forEach(n => validRefs.add(n));
        groupNames.forEach(n => validRefs.add(n));

        userGroups.forEach(userGroup => {
            if (!userGroup?.name) return;

            const existingIndex = findGroupIndexByName(
                this.config['proxy-groups'],
                userGroup.name
            );

            if (existingIndex >= 0) {
                // Merge with existing system group
                const existing = this.config['proxy-groups'][existingIndex];

                // Merge 'use' field (provider references)
                if (Array.isArray(userGroup.use) && userGroup.use.length > 0) {
                    const validUserProviders = userGroup.use.filter(p => allProviderNames.has(p));
                    existing.use = [...new Set([
                        ...(existing.use || []),
                        ...validUserProviders
                    ])];
                }

                // Merge 'proxies' field - validate references first
                if (Array.isArray(userGroup.proxies)) {
                    const validUserProxies = userGroup.proxies.filter(p => validRefs.has(p));
                    existing.proxies = [...new Set([
                        ...(existing.proxies || []),
                        ...validUserProxies
                    ])];
                }

                // Preserve user's custom settings (url, interval)
                if (userGroup.url) existing.url = userGroup.url;
                if (typeof userGroup.interval === 'number') existing.interval = userGroup.interval;
                if (typeof userGroup.lazy === 'boolean') existing.lazy = userGroup.lazy;
            } else {
                // New user-defined group - validate and add
                const newGroup = { ...userGroup };

                // Validate proxies references
                if (Array.isArray(newGroup.proxies)) {
                    newGroup.proxies = newGroup.proxies.filter(p => validRefs.has(p));
                }

                // Validate use (provider) references
                if (Array.isArray(newGroup.use)) {
                    newGroup.use = newGroup.use.filter(p => allProviderNames.has(p));
                }

                if ((newGroup.proxies?.length > 0) || (newGroup.use?.length > 0) || newGroup.type) {
                    this.config['proxy-groups'].push(newGroup);
                }
            }
        });
    }

    /**
     * Reject invalid proxy groups before final output.
     * Why: empty groups make Clash reject the whole config, so we should fail fast
     * instead of masking the upstream merge/parsing problem.
     */
    validateProxyGroups() {
        (this.config['proxy-groups'] || []).forEach(group => {
            const requiresMembers = group?.type === 'url-test' || group?.type === 'fallback';
            if (!requiresMembers) {
                return;
            }

            const hasProxyRefs = Array.isArray(group.proxies) && group.proxies.length > 0;
            const hasProviderRefs = Array.isArray(group.use) && group.use.length > 0;
            if (hasProxyRefs || hasProviderRefs) {
                return;
            }

            const groupName = group?.name || '(unnamed group)';
            throw new InvalidConfigError(
                `Invalid proxy group "${groupName}": type "${group.type}" requires at least one proxy or provider reference`
            );
        });
    }

    // 生成规则
    generateRules() {
        return generateRules(this.selectedRules, this.customRules);
    }

    formatConfig() {
        if (this.skipCertVerify) {
            if (this.getExistingProviderNames().length) {
                throw new InvalidConfigError('skip_cert_verify cannot be applied to preconfigured proxy providers; inline their nodes first');
            }
            // Base-config nodes bypass convertProxy, but must follow the same explicit policy.
            this.config.proxies = this.getProxies().map(proxy => {
                if (proxy['reality-opts'] || !(proxy.tls === true || ['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls'].includes(proxy.type))) return proxy;
                const { fingerprint, ...rest } = proxy;
                return { ...rest, 'skip-cert-verify': true };
            });
        }
        const rules = this.generateRules();
        const useMrs = supportsMrsFormat(this.userAgent);
        const { site_rule_providers, ip_rule_providers } = generateClashRuleSets(this.selectedRules, this.customRules, useMrs);
        this.config['rule-providers'] = {
            ...site_rule_providers,
            ...ip_rule_providers
        };
        const ruleResults = emitClashRules(rules, this.t);

        // Add proxy-providers if we have any
        if (this.providerUrls.length > 0) {
            this.config['proxy-providers'] = {
                ...this.config['proxy-providers'],
                ...this.generateProxyProviders()
            };
        }

        sanitizeClashProxyGroups(this.config);
        this.validateProxyGroups();

        this.config.rules = [
            ...ruleResults,
            `MATCH,${this.t('outboundNames.Fall Back')}`
        ];

        // Enable Clash UI (external controller/dashboard) when requested or when custom UI params are provided
        if (this.enableClashUI || this.externalController || this.externalUiDownloadUrl) {
            const defaultController = '0.0.0.0:9090';
            const defaultUiPath = './ui';
            const defaultUiName = 'zashboard';
            const defaultUiUrl = 'https://gh-proxy.com/https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip';
            const defaultSecret = '';

            const controller = this.externalController || this.config['external-controller'] || defaultController;
            const uiPath = this.config['external-ui'] || defaultUiPath;
            const uiName = this.config['external-ui-name'] || defaultUiName;
            const uiUrl = this.externalUiDownloadUrl || this.config['external-ui-url'] || defaultUiUrl;
            const secret = this.config['secret'] ?? defaultSecret;

            this.config['external-controller'] = controller;
            this.config['external-ui'] = uiPath;
            this.config['external-ui-name'] = uiName;
            this.config['external-ui-url'] = uiUrl;
            this.config['secret'] = secret;
        }

        return yaml.dump(this.config);
    }
}
