import { TrulyAssign } from "../utils/TrulyAssign";
import { parseYAML } from "confbox";
import ClashMetaDumper from "../Dumpers/clash-meta.js";

const BasicConfig = {
    isUDP: true,
    isSSUoT: false,
    isInsecure: true,
    RuleProvider: "https://raw.githubusercontent.com/kobe-koto/EdgeSub/main/public/minimal_remote_rules.ini",
    RuleProvidersProxy: false,
    BaseConfig: "https://raw.githubusercontent.com/kobe-koto/EdgeSub/main/public/basic-config/mihomo.yaml",
    isForcedRefresh: false
}


import { RuleProviderReader } from "../RuleProviderReader/main.js";

export async function getClashMetaConfig (
    Proxies, 
    EdgeSubDB, 
    PassedConfig = {},
) {
    const Config = TrulyAssign(BasicConfig, PassedConfig);

    console.log(`[getClashMetaConfig] fetching base config from remote (${Config.BaseConfig})`)
    const ClashConfig = parseYAML(await fetch(Config.BaseConfig).then(res => res.text()));
    console.log("[getClashMetaConfig] fetched base config", ClashConfig)

    // Mobile DNS compatibility. On many CN mobile networks the domain-based
    // DoH fallbacks (dns.google / cloudflare-dns.com) cannot be bootstrapped,
    // which makes mihomo fail to resolve proxy node domains. Normalize the
    // DNS section so generated configs work on phones out of the box.
    if (ClashConfig.dns) {
        // 1. A `*` entry in fake-ip-filter (blacklist mode) disables fake-ip
        //    for every domain, forcing real DNS resolution for all traffic.
        //    That exposes every query to the fallback chain and breaks on
        //    networks where the fallback endpoints are unreachable. Drop it.
        if (Array.isArray(ClashConfig.dns["fake-ip-filter"])) {
            const cleaned = ClashConfig.dns["fake-ip-filter"].filter(i => i !== "*");
            if (cleaned.length !== ClashConfig.dns["fake-ip-filter"].length) {
                ClashConfig.dns["fake-ip-filter"] = cleaned;
                console.log(`[getClashMetaConfig] removed '*' from dns.fake-ip-filter for mobile compatibility`);
            }
        }

        // 2. Append the domestic default-nameserver to the tail of the
        //    fallback chain (TLS/foreign entries keep priority). They are
        //    reachable on CN mobile networks even when foreign DNS is
        //    blocked, so proxy node resolution never fails outright.
        // 3. Swap domain-based DoH fallbacks for IP-based DoT so they need no
        //    bootstrap lookup.
        if (Array.isArray(ClashConfig.dns.fallback)) {
            const fallback = ClashConfig.dns.fallback.map(String);
            for (const d of (ClashConfig.dns["default-nameserver"] || []).map(String)) {
                if (!fallback.includes(d) && !fallback.includes(`${d}:53`)) {
                    fallback.push(d);
                }
            }
            ClashConfig.dns.fallback = fallback.map(i => {
                if (i === "https://dns.google/dns-query") return "tls://8.8.8.8:853";
                if (i === "https://cloudflare-dns.com/dns-query" || i === "https://mozilla.cloudflare-dns.com/dns-query") return "tls://1.1.1.1:853";
                return i;
            });
        }
    }

    let RuleProvider = await (new RuleProviderReader(Config.RuleProvider)).Process(EdgeSubDB, Config.isForcedRefresh)

    let Dumper = new ClashMetaDumper(Config.isUDP, Config.isSSUoT, Config.isInsecure)
    
    // validate proxies
    Proxies = Proxies.map(i => {
        if (Dumper.__validate(i)) {
            i.Hostname = i.Hostname.replace(/(^\[|\]$)/g, "");
            return i;
        }
    }).filter(i => !!i);
    // append proxies
    ClashConfig.proxies = Proxies.map(i => Dumper[i.__Type](i));

    

    // Append proxy groups.
    ClashConfig["proxy-groups"] = []
    for (let i of RuleProvider.ProxyGroup) {

        // get Matched Proxies
        let MatchedProxies = [];
        for (let t of i.RegExps) {
            MatchedProxies = [ ...MatchedProxies, ...Proxies.filter( loc => loc.__Remark.match(new RegExp(t)) ) ]
        }
        // unique proxy
        MatchedProxies = Array.from(new Set(MatchedProxies));



        // generate proxies list 
        let GroupProxies = [];
        for (let t of i.GroupSelectors) {
            GroupProxies.push(t.replace(/^\[\]/, ""))
        }
        for (let t of MatchedProxies) {
            GroupProxies.push(t.__Remark)
        }
        if (MatchedProxies.length + i.GroupSelectors.length === 0) {
            // add fallback selector if no selector can be added
            GroupProxies.push("DIRECT")
            GroupProxies.push("REJECT")
        }

        //generate proxy group
        let ProxyGroup = {}
        ProxyGroup.name = i.name;
        ProxyGroup.type = i.type;
        if (i.type === "url-test" || i.type === "load-balance" || i.type === "fallback") {
            ProxyGroup.url = i.TestConfig.TestURL;
            ProxyGroup.interval = i.TestConfig.Interval;
        }
        if (i.type === "url-test") {
            ProxyGroup.tolerance = i.TestConfig.Tolerance;
        }
        ProxyGroup.proxies = GroupProxies;

        // append proxy group to config
        ClashConfig["proxy-groups"].push(ProxyGroup)
    }

    // append rule providers
    ClashConfig["rule-providers"] = {};
    let RuleProvidersMapping = {}; // { URL: ID }[]
    for (let i in RuleProvider.RuleProviders) {
        for (let t in RuleProvider.RuleProviders[i]) {
            const RuleProviderPayload = RuleProvider.RuleProviders[i][t];
            const RuleProviderID = `${i}__${t}`;
            RuleProvidersMapping[RuleProviderPayload] = RuleProviderID;
            let RuleProviderURL;
            if (Config.RuleProvidersProxy) {
                let RuleProviderURLObject = new URL(Config.RuleProvidersProxy);
                RuleProviderURLObject.pathname = "/ruleset/proxy"
                RuleProviderURLObject.search = ""
                RuleProviderURLObject.searchParams.append("target", RuleProviderPayload)
                RuleProviderURL = RuleProviderURLObject.toString()
            } else {
                RuleProviderURL = RuleProviderPayload;
            }
            ClashConfig["rule-providers"][RuleProviderID] = {
                type: "http",
                behavior: "classical",
                url: RuleProviderURL,
                format: (RuleProviderPayload.endsWith(".yaml") || RuleProviderPayload.endsWith(".yml")) ? "yaml" : "text",
                interval: 21600
            }
        }
    }

    // Append rule sets;
    ClashConfig.rules = []
    for (let i of RuleProvider.Rules) {
        
        const rulesetBreakdown = i.split(",")
        const id = rulesetBreakdown[0];
        let payload = rulesetBreakdown.slice(1).join(",");
        if (payload.startsWith("http://") || payload.startsWith("https://")) {
            payload = `RULE-SET,${RuleProvidersMapping[payload]}`;
        }
        ClashConfig.rules.push(`${payload},${id}`)
    }

    return ClashConfig;
}
