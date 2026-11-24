package views

// What the data goldens were rendered from, held as test input. The Rust
// server rendered them from the state of rust-v17.sqlite3 and, for the
// registry, from the live AdGuard registry.

type registryGroup struct {
	GroupID   int64
	GroupName string
}

type registryFilter struct {
	FilterID    int64
	GroupID     int64
	Name        string
	Description string
	Homepage    string
	Deprecated  bool
}

// The registry as the Rust server fetched it (66 filters), without the fields
// the page does not show.
var registryGroups = []registryGroup{
	{GroupID: 1, GroupName: "General"},
	{GroupID: 2, GroupName: "Other"},
	{GroupID: 3, GroupName: "Regional"},
	{GroupID: 4, GroupName: "Security"},
}

var registryFilters = []registryFilter{
	{FilterID: 1, GroupID: 1, Name: "AdGuard DNS filter", Description: "List composed of several filters (AdGuard Base filter, Social Media filter, Tracking Protection filter, Mobile Ads filter, EasyList and EasyPrivacy) and simplified specifically to be better compatible with DNS-level ad blocking", Homepage: "https://github.com/AdguardTeam/AdGuardSDNSFilter"},
	{FilterID: 24, GroupID: 1, Name: "1Hosts (Lite)", Description: "List for blocking pesky ads, trackers, and malware. Balanced version: set & forget, doesn't hamper user experience.", Homepage: "https://badmojr.github.io/1Hosts/"},
	{FilterID: 27, GroupID: 1, Name: "OISD Blocklist Big", Description: "List for blocking ads and trackers. Prioritizes functionality over blocking. Risks of incorrect blocking are higher than in the small version of OISD Blocklist.", Homepage: "https://oisd.nl/"},
	{FilterID: 33, GroupID: 1, Name: "Steven Black's List", Description: "Unified hosts file (adware + malware).", Homepage: "https://github.com/StevenBlack/hosts"},
	{FilterID: 34, GroupID: 1, Name: "HaGeZi's Normal Blocklist", Description: "Broom - Cleans the Internet and protects your privacy! Blocks Ads, Affiliate, Tracking, Metrics, Telemetry, Phishing, Malware, Scam, Fake, Coins and other Crap.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 3, GroupID: 1, Name: "Peter Lowe's Blocklist", Description: "Blocklist with hostnames of ad and tracking servers", Homepage: "https://pgl.yoyo.org/adservers/"},
	{FilterID: 48, GroupID: 1, Name: "HaGeZi's Pro Blocklist", Description: "Big broom - Cleans the Internet and protects your privacy! Blocks Ads, Affiliate, Tracking, Metrics, Telemetry, Phishing, Malware, Scam, Fake, Coins and other Crap.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 49, GroupID: 1, Name: "HaGeZi's Ultimate Blocklist", Description: "Ultimate Sweeper - Strictly cleans the Internet and protects your privacy! Blocks Ads, Affiliate, Tracking (+Referral), Metrics, Telemetry, Phishing, Malware, Scam, Free Hoster, Fake, Coins and other Crap.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 4, GroupID: 1, Name: "Dan Pollock's List", Description: "List for blocking ads and preventing user tracking", Homepage: "https://someonewhocares.org/"},
	{FilterID: 51, GroupID: 1, Name: "HaGeZi's Pro++ Blocklist", Description: "Sweeper - Aggressive cleans the Internet and protects your privacy! Blocks Ads, Affiliate, Tracking, Metrics, Telemetry, Phishing, Malware, Scam, Fake, Coins and other Crap.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 53, GroupID: 1, Name: "AWAvenue Ads Rule", Description: "Uses Adblock syntax to fight against various advertising SDKs in Android apps on the network level, preventing them from loading.", Homepage: "https://awavenue.top/"},
	{FilterID: 59, GroupID: 1, Name: "AdGuard DNS Popup Hosts filter", Description: "Filter includes rules for sites that open in a new window, composed from AdGuard, EasyList, ABPindo filters and improved for compatibility with DNS-level pop-up blocking.", Homepage: "https://github.com/AdguardTeam/AdGuardSDNSFilter"},
	{FilterID: 5, GroupID: 1, Name: "OISD Blocklist Small", Description: "List for blocking ads and trackers. Prioritizes functionality over blocking.", Homepage: "https://oisd.nl/"},
	{FilterID: 69, GroupID: 1, Name: "ShadowWhisperer Tracking List", Description: "Blocks domains related to analytics, diagnostics, metrics, location, and public IP detection.", Homepage: "https://github.com/ShadowWhisperer/BlockLists"},
	{FilterID: 70, GroupID: 1, Name: "1Hosts (Xtra)", Description: "Aggressive version - maximum blocking against emerging privacy threats. May (occasionally) disrupt legit sites or services.", Homepage: "https://badmojr.github.io/1Hosts/"},
	{FilterID: 37, GroupID: 2, Name: "No Google", Description: "Completely blocks all Google-related domains (including YouTube).", Homepage: "https://github.com/nickspaargaren/no-google"},
	{FilterID: 39, GroupID: 2, Name: "Dandelion Sprout's Anti Push Notifications", Description: "Aims to remove push notifications on sites. Combines eligible rules from AdGuard Popups Filter's anti-push sections and Fanboy's Notifications Blocking List.", Homepage: "https://github.com/DandelionSprout/adfilt"},
	{FilterID: 45, GroupID: 2, Name: "HaGeZi's Allowlist Referral", Description: "This list unblocks affiliate & tracking referral links that appear in mails, search results etc.", Homepage: "https://github.com/hagezi/dns-blocklists#referral"},
	{FilterID: 46, GroupID: 2, Name: "HaGeZi's Anti-Piracy Blocklist", Description: "Blocks websites and services that are mainly used for illegal distribution of copyrighted content.", Homepage: "https://github.com/hagezi/dns-blocklists#piracy"},
	{FilterID: 47, GroupID: 2, Name: "HaGeZi's Gambling Blocklist", Description: "Blocks gambling content.", Homepage: "https://github.com/hagezi/dns-blocklists#gambling"},
	{FilterID: 57, GroupID: 2, Name: "ShadowWhisperer's Dating List", Description: "Blocks dating websites.", Homepage: "https://github.com/ShadowWhisperer/BlockLists"},
	{FilterID: 60, GroupID: 2, Name: "HaGeZi's Xiaomi Tracker Blocklist", Description: "Blocks Xiaomi native broadband trackers that track your activity.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 61, GroupID: 2, Name: "HaGeZi's Samsung Tracker Blocklist", Description: "Blocks Samsung native broadband trackers that track your activity.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 63, GroupID: 2, Name: "HaGeZi's Windows/Office Tracker Blocklist", Description: "Blocks Windows/Office native broadband trackers that track your activity.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 65, GroupID: 2, Name: "HaGeZi's Vivo Tracker Blocklist", Description: "Blocks Vivo native broadband trackers that track your activity.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 66, GroupID: 2, Name: "HaGeZi's OPPO & Realme Tracker Blocklist", Description: "Blocks OPPO & Realme native broadband trackers that track your activity.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 67, GroupID: 2, Name: "HaGeZi's Apple Tracker Blocklist", Description: "Blocks Apple native broadband trackers that track your activity.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 6, GroupID: 2, Name: "Dandelion Sprout's Game Console Adblock List", Description: "List for blocking ads on videogame consoles that use AdGuard Home", Homepage: "https://github.com/DandelionSprout/adfilt"},
	{FilterID: 72, GroupID: 2, Name: "HaGeZi's LG webOS Tracker Blocklist", Description: "Blocks LG webOS native trackers built into devices, services, and operating systems that track your activity.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 73, GroupID: 2, Name: "HaGeZi's Huawei Tracker Blocklist", Description: "Blocks Huawei native trackers built into devices, services, and operating systems that track your activity.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 7, GroupID: 2, Name: "Perflyst and Dandelion Sprout's Smart-TV Blocklist", Description: "List for preventing smart TVs from sending metadata to the vendor, and for blocking ads in apps and movie services", Homepage: "https://github.com/Perflyst/PiHoleBlocklist"},
	{FilterID: 13, GroupID: 3, Name: "NOR: Dandelion Sprouts nordiske filtre", Description: "Dandelion Sprout's Nordic Filters (DNS filtering in AdGuard Home, AdGuard for Android, and AdGuard for Windows)", Homepage: "https://github.com/DandelionSprout/adfilt"},
	{FilterID: 14, GroupID: 3, Name: "POL: Polish filters for Pi-hole", Description: "Polish filters for Pi-hole.", Homepage: "https://www.certyficate.it/"},
	{FilterID: 15, GroupID: 3, Name: "KOR: YousList", Description: "List for blocking ads mainly on Korean websites", Homepage: "https://github.com/yous/YousList"},
	{FilterID: 16, GroupID: 3, Name: "VNM: ABPVN List", Description: "List for blocking ads on Vietnamese websites", Homepage: "http://abpvn.com/"},
	{FilterID: 17, GroupID: 3, Name: "SWE: Frellwit's Swedish Hosts File", Description: "List for blocking ads, tracking, scams & malware mainly on Swedish websites", Homepage: "https://github.com/lassekongo83/Frellwits-filter-lists/"},
	{FilterID: 19, GroupID: 3, Name: "IRN: PersianBlocker list", Description: "Optimal and extensive list for blocking ads and trackers on Persian language sites", Homepage: "https://github.com/PersianBlocker/PersianBlocker"},
	{FilterID: 20, GroupID: 3, Name: "MKD: Macedonian Pi-hole Blocklist", Description: "List for blocking ads on Macedonian websites", Homepage: "https://github.com/cchevy/macedonian-pi-hole-blocklist"},
	{FilterID: 21, GroupID: 3, Name: "CHN: anti-AD", Description: "List for blocking ads in the Chinese region. Aims at privacy protection.", Homepage: "https://anti-ad.net/"},
	{FilterID: 22, GroupID: 3, Name: "IDN: ABPindo", Description: "Filter complementary to EasyList for blocking ads on Indonesian and Malaysian websites", Homepage: "https://github.com/ABPindo/indonesianadblockrules"},
	{FilterID: 25, GroupID: 3, Name: "KOR: filterslists-KO", Description: "A DNS version of filterslist-KO, a filter for Korean-language websites.", Homepage: "https://github.com/FilteringDev/filterslists-KO"},
	{FilterID: 26, GroupID: 3, Name: "TUR: turk-adlist", Description: "List for blocking ads and annoying elements on Turkish websites", Homepage: "https://github.com/bkrucarci/turk-adlist"},
	{FilterID: 29, GroupID: 3, Name: "CHN: AdRules DNS List", Description: "List for blocking ads in the Chinese region", Homepage: "https://github.com/Cats-Team/AdRules"},
	{FilterID: 35, GroupID: 3, Name: "HUN: Hufilter", Description: "The Hungarian Adblock List.", Homepage: "https://github.com/hufilter/hufilter"},
	{FilterID: 36, GroupID: 3, Name: "LIT: EasyList Lithuania", Description: "This is a (currently pretty small and not much tested) version of EasyList Lithuania designed for use with domains-based tools.", Homepage: "https://github.com/EasyList-Lithuania/easylist_lithuania"},
	{FilterID: 40, GroupID: 3, Name: "TUR: Turkish Ad Hosts", Description: "Necessary hosts file to block tracking and possibly advertising networks in commonly used mobile apps (and possibly web pages) in Turkey.", Homepage: "https://github.com/symbuzzer/Turkish-Ad-Hosts"},
	{FilterID: 41, GroupID: 3, Name: "POL: CERT Polska List of malicious domains", Description: "CERT Polska deals with incidents and threats originating or aiming at systems in the .pl domain or connected to NASK's or other Polish Internet provider's network.", Homepage: "https://cert.pl/posts/2020/03/ostrzezenia_phishing/"},
	{FilterID: 43, GroupID: 3, Name: "ISR: EasyList Hebrew", Description: "List for blocking ads in Hebrew.", Homepage: "https://github.com/easylist/EasyListHebrew"},
	{FilterID: 62, GroupID: 3, Name: "Ukrainian Security Filter", Description: "Filters malicious web resources (phishing, online fraud, malware, etc.) targeting Ukrainian citizens", Homepage: "https://github.com/braveinnovators/ukrainian-security-filter"},
	{FilterID: 10, GroupID: 4, Name: "Scam Blocklist by DurableNapkin", Description: "List for blocking untrustworthy websites", Homepage: "https://github.com/durablenapkin/scamblocklist"},
	{FilterID: 11, GroupID: 4, Name: "Malicious URL Blocklist (URLHaus)", Description: "Blocklist of malicious websites based on the Database dump of Abuse.ch URLhaus", Homepage: "https://urlhaus.abuse.ch/"},
	{FilterID: 12, GroupID: 4, Name: "Dandelion Sprout's Anti-Malware List", Description: "Dandelion Sprout's Anti-Malware List (DNS filtering in AdGuard Home, AdGuard for Android, and AdGuard for Windows)", Homepage: "https://github.com/DandelionSprout/adfilt"},
	{FilterID: 18, GroupID: 4, Name: "Phishing Army", Description: "The blocklist to filter phishing domains", Homepage: "https://phishing.army/"},
	{FilterID: 30, GroupID: 4, Name: "Phishing URL Blocklist (PhishTank and OpenPhish)", Description: "Blocklist of phishing websites, based on PhishTank and OpenPhish lists", Homepage: "https://gitlab.com/malware-filter/phishing-filter"},
	{FilterID: 31, GroupID: 4, Name: "Stalkerware Indicators List", Description: "Indicators of compromise on Stalkerware applications for Android and iOS.", Homepage: "https://github.com/AssoEchap/stalkerware-indicators"},
	{FilterID: 42, GroupID: 4, Name: "ShadowWhisperer's Malware List", Description: "Malicious Sites, PUPs, Malware, Browser Hijackers, Phishing Sites", Homepage: "https://github.com/ShadowWhisperer/BlockLists"},
	{FilterID: 44, GroupID: 4, Name: "HaGeZi's Threat Intelligence Feeds", Description: "Increases security significantly! Blocks Malware, Cryptojacking, Spam, Scam and Phishing.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 50, GroupID: 4, Name: "uBlock₀ filters – Badware risks", Description: "For sites documented to put users at risk of installing adware/crapware/malware, having login credentials stolen, etc. The purpose is to at least ensure a user is warned of the risks ahead.", Homepage: "https://github.com/uBlockOrigin/uAssets"},
	{FilterID: 52, GroupID: 4, Name: "HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass", Description: "Prevents methods to bypass your DNS, blocks encrypted DNS, VPN, TOR, and proxies. Prevention of bypassing is not guaranteed.", Homepage: "https://github.com/hagezi/dns-blocklists#bypass"},
	{FilterID: 54, GroupID: 4, Name: "HaGeZi's DynDNS Blocklist", Description: "Blocks dynamic DNS services to protect against malicious use in phishing campaigns and others.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 55, GroupID: 4, Name: "HaGeZi's Badware Hoster Blocklist", Description: "Blocks known free hosters that also host badware via user content to prevent the use of these hosters for malicious purposes.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 56, GroupID: 4, Name: "HaGeZi's The World's Most Abused TLDs", Description: "The Top Most Abused Top Level Domains, merged from HaGeZi, Yokoffing, DandelionSprout and SpamHAUS.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 68, GroupID: 4, Name: "HaGeZi's URL Shortener Blocklist", Description: "Blocks URL shorteners.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 71, GroupID: 4, Name: "HaGeZi's DNS Rebind Protection", Description: "DNS Rebind Protection is a security mechanism that prevents attackers from manipulating DNS responses to make a domain resolve to private or local IP addresses, thereby blocking malicious scripts from accessing internal networks through DNS rebinding attacks.", Homepage: "https://github.com/hagezi/dns-blocklists"},
	{FilterID: 8, GroupID: 4, Name: "NoCoin Filter List", Description: "List for blocking browser-based crypto mining", Homepage: "https://github.com/hoshsadiq/adblock-nocoin-list/"},
	{FilterID: 9, GroupID: 4, Name: "The Big List of Hacked Malware Web Sites", Description: "List of websites that are hacked with malware, ransomware or trojans", Homepage: "https://github.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites"},
}

// The query log pages. One row per line: flags (b blocked, c cached, d DNSSEC,
// - none), domain, query type, result, DoH token, upstream, response ms. Every
// row came from 192.168.215.1; the action each row offers follows from whether
// it was blocked (see parseLogRows).
const logRowsFirstPage = `
b|ads.example.com|AAAA|::|||0
b|ads.example.com|A|0.0.0.0|beta-token||0
c|allowed.example.com|MX|10 mail.example.com.|||0
c|allowed.example.com|AAAA|2001:db8::1|alpha-token||0
c|allowed.example.com|A|93.184.216.34, 93.184.216.35|||0
b|telemetry.list-one.test|AAAA|::|beta-token||0
c|ok.ads.example.com|A|198.51.100.1|||0
cd|dnssec.example.com|A|192.0.2.9|alpha-token||0
c|cname.example.com|A|target.example.com., 192.0.2.7|||0
c|nodata.example.com|A||beta-token||0
c|nxd.example.com|A||||0
c|ok.list-two.test|A|198.51.100.1|alpha-token||0
b|adserver.list-two.test|A|0.0.0.0|||0
b|ads.list-one.test|A|0.0.0.0|beta-token||0
b|tracker.example.net|A|0.0.0.0|||0
b|ads.example.com|AAAA|::|alpha-token||0
b|ads.example.com|A|0.0.0.0|||0
c|allowed.example.com|MX|10 mail.example.com.|beta-token||0
c|allowed.example.com|AAAA|2001:db8::1|||0
c|allowed.example.com|A|93.184.216.34, 93.184.216.35|alpha-token||0
b|telemetry.list-one.test|AAAA|::|||0
c|ok.ads.example.com|A|198.51.100.1|beta-token||0
cd|dnssec.example.com|A|192.0.2.9|||0
c|cname.example.com|A|target.example.com., 192.0.2.7|alpha-token||0
c|nodata.example.com|A||||0
c|nxd.example.com|A||beta-token||0
c|ok.list-two.test|A|198.51.100.1|||0
b|adserver.list-two.test|A|0.0.0.0|alpha-token||0
b|ads.list-one.test|A|0.0.0.0|||0
b|tracker.example.net|A|0.0.0.0|beta-token||0
b|ads.example.com|AAAA|::|||0
b|ads.example.com|A|0.0.0.0|alpha-token||0
c|allowed.example.com|MX|10 mail.example.com.|||0
c|allowed.example.com|AAAA|2001:db8::1|beta-token||0
c|allowed.example.com|A|93.184.216.34, 93.184.216.35|||0
b|telemetry.list-one.test|AAAA|::|alpha-token||0
c|ok.ads.example.com|A|198.51.100.1|||0
cd|dnssec.example.com|A|192.0.2.9|beta-token||0
c|cname.example.com|A|target.example.com., 192.0.2.7|||0
c|nodata.example.com|A||alpha-token||0
c|nxd.example.com|A||||0
c|ok.list-two.test|A|198.51.100.1|beta-token||0
b|adserver.list-two.test|A|0.0.0.0|||0
b|ads.list-one.test|A|0.0.0.0|alpha-token||0
b|tracker.example.net|A|0.0.0.0|||0
b|ads.example.com|AAAA|::|beta-token||0
b|ads.example.com|A|0.0.0.0|||0
c|allowed.example.com|MX|10 mail.example.com.|alpha-token||0
c|allowed.example.com|AAAA|2001:db8::1|||0
c|allowed.example.com|A|93.184.216.34, 93.184.216.35|beta-token||0
`

const logRowsWildcardPage = `
cd|dnssec.example.com|A|192.0.2.9|alpha-token||0
c|cname.example.com|A|target.example.com., 192.0.2.7|||0
c|nodata.example.com|A||beta-token||0
c|nxd.example.com|A||||0
b|tracker.example.net|A|0.0.0.0|||0
b|ads.example.com|AAAA|::|alpha-token||0
b|ads.example.com|A|0.0.0.0|||0
c|allowed.example.com|MX|10 mail.example.com.|beta-token||0
c|allowed.example.com|AAAA|2001:db8::1|||0
c|allowed.example.com|A|93.184.216.34, 93.184.216.35|alpha-token||0
c|ok.ads.example.com|A|198.51.100.1|beta-token||0
cd|dnssec.example.com|A|192.0.2.9|||0
c|cname.example.com|A|target.example.com., 192.0.2.7|alpha-token||0
c|nodata.example.com|A||||0
c|nxd.example.com|A||beta-token||0
b|tracker.example.net|A|0.0.0.0|beta-token||0
b|ads.example.com|AAAA|::|||0
b|ads.example.com|A|0.0.0.0|alpha-token||0
c|allowed.example.com|MX|10 mail.example.com.|||0
c|allowed.example.com|AAAA|2001:db8::1|beta-token||0
c|allowed.example.com|A|93.184.216.34, 93.184.216.35|||0
c|ok.ads.example.com|A|198.51.100.1|||0
cd|dnssec.example.com|A|192.0.2.9|beta-token||0
c|cname.example.com|A|target.example.com., 192.0.2.7|||0
c|nodata.example.com|A||alpha-token||0
c|nxd.example.com|A||||0
b|tracker.example.net|A|0.0.0.0|||0
b|ads.example.com|AAAA|::|beta-token||0
b|ads.example.com|A|0.0.0.0|||0
c|allowed.example.com|MX|10 mail.example.com.|alpha-token||0
c|allowed.example.com|AAAA|2001:db8::1|||0
c|allowed.example.com|A|93.184.216.34, 93.184.216.35|beta-token||0
c|ok.ads.example.com|A|198.51.100.1|alpha-token||0
cd|dnssec.example.com|A|192.0.2.9|||0
c|cname.example.com|A|target.example.com., 192.0.2.7|beta-token||0
c|nodata.example.com|A||||0
c|nxd.example.com|A||alpha-token||0
b|tracker.example.net|A|0.0.0.0|alpha-token||0
b|ads.example.com|AAAA|::|||0
b|ads.example.com|A|0.0.0.0|beta-token||0
c|allowed.example.com|MX|10 mail.example.com.|||0
c|allowed.example.com|AAAA|2001:db8::1|alpha-token||0
c|allowed.example.com|A|93.184.216.34, 93.184.216.35|||0
c|ok.ads.example.com|A|198.51.100.1|||0
cd|dnssec.example.com|A|192.0.2.9|alpha-token||0
c|cname.example.com|A|target.example.com., 192.0.2.7|||0
c|nodata.example.com|A||beta-token||0
c|nxd.example.com|A||||0
b|tracker.example.net|A|0.0.0.0|||0
b|ads.example.com|AAAA|::|alpha-token||0
`

const logRowsFiltered = `
b|adserver.list-two.test|A|0.0.0.0|alpha-token||0
b|ads.example.com|A|0.0.0.0|alpha-token||0
b|ads.list-one.test|A|0.0.0.0|alpha-token||0
b|adserver.list-two.test|A|0.0.0.0|alpha-token||0
b|ads.example.com|A|0.0.0.0|alpha-token||0
b|ads.list-one.test|A|0.0.0.0|alpha-token||0
b|adserver.list-two.test|A|0.0.0.0|alpha-token||0
b|ads.example.com|A|0.0.0.0|alpha-token||0
b|ads.list-one.test|A|0.0.0.0|alpha-token||0
`
