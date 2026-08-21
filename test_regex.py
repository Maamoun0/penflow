import urllib.request
import re

HTML_SRC_PATTERN = re.compile(
    r'(?:src|href|action|srcset|data-url|data-src|data-href|data-endpoint|formaction)\s*=\s*(?:["\']([^"\']+)["\']|([^\s>"\']+))',
    re.IGNORECASE
)

url = 'https://0a5900bf0300f83a81347fbf003c0077.web-security-academy.net/'
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
try:
    html = urllib.request.urlopen(req).read().decode('utf-8')
    print('HTML length:', len(html))
    links = HTML_SRC_PATTERN.findall(html)
    print('Found links:', len(links))
    for l in links[:10]:
        print(l)
except Exception as e:
    print('Error:', e)
