# WAF Rules Cloudflare

This list is mostly taken and adapted from: https://github.com/sefinek/Cloudflare-WAF-Expressions

### Block Common Scan Patterns: Predecence: 1, Action: Block

```js
(http.request.uri.path contains "\\") or
(http.request.uri.path contains "%5c") or
(http.request.uri.path contains "%2f") or
(http.request.uri.path eq "/backup") or
(http.request.uri.path eq "/git") or
(http.request.uri.path eq "/old") or
(http.request.uri.path wildcard "*.env*") or
(http.request.uri.path wildcard "*.log*") or
(http.request.uri.path wildcard "*.py*") or
(http.request.uri.path wildcard "*.sh*") or
(http.request.uri.path wildcard "*.yaml*") or
(http.request.uri.path wildcard "*.yml*") or
(http.request.uri.path wildcard "*auth.json*") or
(http.request.uri.path wildcard "*conf.*") or
(http.request.uri.path wildcard "*crlfinjection*") or
(http.request.uri.path wildcard "*curl%20*") or
(http.request.uri.path wildcard "*curl+*") or
(http.request.uri.path wildcard "*fancyupload*") or
(http.request.uri.path wildcard "*openai.yaml*") or
(http.request.uri.path wildcard "*php.ini*") or
(http.request.uri.path wildcard "*phpinfo*") or
(http.request.uri.path wildcard "*.php*") or
(http.request.uri.path wildcard "*phpsysinfo*") or
(http.request.uri.path wildcard "*settings.local*") or
(http.request.uri.path wildcard "*settings.prod*") or
(http.request.uri.path wildcard "*wget%20*") or
(http.request.uri.path wildcard "*wget+*") or
(http.request.uri.path wildcard "*passwd*") or
(http.request.uri.path wildcard "*shadow*") or
(http.request.uri.path wildcard "*proc/self*") or
(http.request.uri.path wildcard "*metadata.google.internal*") or
(http.request.uri.path wildcard "*169.254.169.254*") or
(http.request.uri.path wildcard "*composer.json*") or
(http.request.uri.path wildcard "*package-lock.json*") or
(http.request.uri.path wildcard "*/.*" and not starts_with(http.request.uri.path, "/.well-known/")) or
(http.request.uri.path wildcard "*//*") or
(http.request.uri.path wildcard "*/actuator*") or
(http.request.uri.path wildcard "*/wp-content*") or
(http.request.uri.path wildcard "*/wp-login*") or
(http.request.uri.path wildcard "*/wp-json*") or
(http.request.uri.path wildcard "*/dbadmin*") or
(http.request.uri.path wildcard "*/debug*") or
(http.request.uri.path wildcard "*/etc/passwd") or
(http.request.uri.path wildcard "*/phpmyadmin*") or
(http.request.uri.path wildcard "*/readme*") or
(http.request.uri.path wildcard "*/sito*") or
(http.request.uri.path wildcard "*/ssh*") or
(http.request.uri.path wildcard "*/webdav*") or
(http.request.uri.path wildcard "*/~adm*") or
(http.request.uri.path wildcard "*/~sysadm*") or
(http.request.uri.path wildcard "*/~webmaster*") or
(http.request.uri.path wildcard "*appsettings*") or
(http.request.uri.path wildcard "*authorized_keys*") or
(http.request.uri.path wildcard "*backup.*") or
(http.request.uri.path wildcard "*docker-compose*") or
(http.request.uri.path wildcard "*dockerfile*") or
(http.request.uri.path wildcard "*dump.*") or
(http.request.uri.path wildcard "*file_put_contents*") or
(http.request.uri.path wildcard "*id_rsa*") or
(http.request.uri.path wildcard "*keys.json*") or
(http.request.uri.path wildcard "*pboot:if*") or
(http.request.uri.path wildcard "*server.key*") or
(http.request.uri.path wildcard "*sftp*") or
(http.request.uri.path wildcard "*wlwmanifest*") or
(http.request.uri.path wildcard "*www-sql*") or
(http.request.uri.path wildcard "*_all_dbs*") or
(http.request.uri.path wildcard "*_debugbar*") or
(http.request.uri.path wildcard "*~ftp*") or
(http.request.uri.path wildcard "*~tmp*") or
(http.request.uri.path wildcard "*.asp") or
(http.request.uri.path wildcard "*.aspx") or
(http.request.uri.path wildcard "*.asa") or
(http.request.uri.path wildcard "*.asax") or
(http.request.uri.path wildcard "*global.asa*") or
(http.request.uri.path wildcard "*web.config*") or
(http.request.uri.path wildcard "*trace.axd*") or
(http.request.uri.path wildcard "*elmah.axd*")
```

#### Block Suspicious Queries & Malicious User-Agents: Precedence 2, Action: block

```js
(http.request.uri.query contains "%00") or
(http.request.uri.query contains "%0A") or
(http.request.uri.query contains "%0D") or
(http.request.uri.query contains "%2e%2e") or
(http.request.uri.query contains "..%2f") or
(http.request.uri.query contains "..%5c") or
(http.request.uri.query contains "../") or
(http.request.uri.query contains "..\\") or
(http.request.uri.query contains "squelette=../") or
(http.request.uri.query wildcard "*auto_prepend_file*") or
(http.request.uri.query wildcard "*crlfinjection*") or
(http.request.uri.query wildcard "*curl%20*") or
(http.request.uri.query wildcard "*curl+*") or
(http.request.uri.query wildcard "*ed25519*") or
(http.request.uri.query wildcard "*file://*") or
(http.request.uri.query wildcard "*php://*") or
(http.request.uri.query wildcard "*secrets.json*") or
(http.request.uri.query wildcard "*set-cookie:*") or
(http.request.uri.query wildcard "*wget%20*") or
(http.request.uri.query wildcard "*wget+*") or
(http.user_agent eq "") or
(http.user_agent contains "  ") or
(http.user_agent wildcard "*headless*") or
(http.user_agent wildcard "*hesbot*") or
(http.user_agent wildcard "*ruby*") or
(http.user_agent wildcard "*aiohttp*") or
(http.user_agent wildcard "*curl*") or
(http.user_agent wildcard "*okhttp*") or
(http.user_agent wildcard "*python-requests*") or
(http.user_agent wildcard "*python-httpx*") or
(http.user_agent wildcard "*node*") or
(http.user_agent wildcard "*wget*") or
(http.user_agent wildcard "*alittle client*") or
(http.user_agent wildcard "*example.com*") or
(http.user_agent wildcard "*php7.4-global*")
```

#### Block Legacy & Suspicious Browsers: Precedence 3, Action: Managed Challenge

#### NOTE: On high traffic websites, this might cause false positives from users using outdated browsers.

```js
(http.user_agent wildcard "*android 8*") or
(http.user_agent wildcard "*chrome/17*") or
(http.user_agent wildcard "*chrome/30*") or
(http.user_agent wildcard "*chrome/31*") or
(http.user_agent wildcard "*chrome/32*") or
(http.user_agent wildcard "*chrome/33*") or
(http.user_agent wildcard "*chrome/34*") or
(http.user_agent wildcard "*chrome/35*") or
(http.user_agent wildcard "*chrome/36*") or
(http.user_agent wildcard "*chrome/37*") or
(http.user_agent wildcard "*chrome/38*") or
(http.user_agent wildcard "*chrome/39*") or
(http.user_agent wildcard "*chrome/41*") or
(http.user_agent wildcard "*chrome/42*") or
(http.user_agent wildcard "*chrome/44*") or
(http.user_agent wildcard "*chrome/48*") or
(http.user_agent wildcard "*chrome/49*") or
(http.user_agent wildcard "*chrome/52*") or
(http.user_agent wildcard "*chrome/53*") or
(http.user_agent wildcard "*chrome/58*") or
(http.user_agent wildcard "*chrome/60*") or
(http.user_agent wildcard "*chrome/61*") or
(http.user_agent wildcard "*chrome/62*") or
(http.user_agent wildcard "*chrome/64*") or
(http.user_agent wildcard "*chrome/65*") or
(http.user_agent wildcard "*chrome/67*") or
(http.user_agent wildcard "*chrome/68*") or
(http.user_agent wildcard "*chrome/69*") or
(http.user_agent wildcard "*chrome/71*") or
(http.user_agent wildcard "*chrome/73*") or
(http.user_agent wildcard "*chrome/74*" and not http.user_agent contains "Better Uptime Bot") or
(http.user_agent wildcard "*chrome/77*") or
(http.user_agent wildcard "*chrome/78*") or
(http.user_agent wildcard "*chrome/79*") or
(http.user_agent wildcard "*chrome/80*") or
(http.user_agent wildcard "*chrome/81*") or
(http.user_agent wildcard "*chrome/83*") or
(http.user_agent wildcard "*chrome/84*") or
(http.user_agent wildcard "*chrome/85*") or
(http.user_agent wildcard "*chrome/86*") or
(http.user_agent wildcard "*chrome/87*") or
(http.user_agent wildcard "*chrome/88*") or
(http.user_agent wildcard "*chrome/89*") or
(http.user_agent wildcard "*chrome/91*") or
(http.user_agent wildcard "*chrome/92*") or
(http.user_agent wildcard "*chrome/93*") or
(http.user_agent wildcard "*chrome/94*") or
(http.user_agent wildcard "*chrome/95*") or
(http.user_agent wildcard "*chrome/96*") or
(http.user_agent wildcard "*chrome/97*") or
(http.user_agent wildcard "*chrome/98*") or
(http.user_agent wildcard "*crios/121*") or
(http.user_agent wildcard "*firefox/114*") or
(http.user_agent wildcard "*firefox/3.5*") or
(http.user_agent wildcard "*firefox/45*") or
(http.user_agent wildcard "*firefox/52*") or
(http.user_agent wildcard "*firefox/57*") or
(http.user_agent wildcard "*firefox/62*") or
(http.user_agent wildcard "*firefox/76*") or
(http.user_agent wildcard "*firefox/77*") or
(http.user_agent wildcard "*firefox/79*") or
(http.user_agent wildcard "*firefox/83*") or
(http.user_agent wildcard "*firefox/84*") or
(http.user_agent wildcard "*html5plus*") or
(http.user_agent wildcard "*mac os x 10_9*") or
(http.user_agent wildcard "*msie 9.0*") or
(http.user_agent wildcard "*msie*") or
(http.user_agent wildcard "*netfront*") or
(http.user_agent wildcard "*symbianos*") or
(http.user_agent wildcard "*trident/")
```
