const os = require('os');
const http = require('http');

let cachedPublicUrl = process.env.PUBLIC_URL || null;
let cachedNgrokUrl = null;

function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address;
    }
  }
  return '127.0.0.1';
}

function getHostname() {
  return os.hostname().toLowerCase().replace(/\.local$/, '') + '.local';
}

function setNgrokUrl(url) {
  cachedNgrokUrl = url;
  if (!process.env.PUBLIC_URL) cachedPublicUrl = url;
}

function getNgrokUrl(timeout = 2000) {
  return new Promise((resolve) => {
    if (cachedNgrokUrl) return resolve(cachedNgrokUrl);
    const req = http.get('http://127.0.0.1:4040/api/tunnels', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const tunnels = JSON.parse(data).tunnels || [];
          const httpsTunnel = tunnels.find(t => t.public_url && t.public_url.startsWith('https://'));
          if (httpsTunnel) { setNgrokUrl(httpsTunnel.public_url); resolve(httpsTunnel.public_url); }
          else resolve(null);
        } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(timeout, () => { req.destroy(); resolve(null); });
  });
}

function getPublicUrl(req) {
  if (cachedPublicUrl) return cachedPublicUrl.replace(/\/+$/, '');
  const port = process.env.PORT || 3000;
  const hostname = getHostname();
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host = (req.get('host') || '').toLowerCase();
  const isLocal = host.startsWith('localhost') || host.startsWith('127.0.0.1') || host === '::1';
  if (isLocal) {
    const localIP = getLocalIP();
    return `${protocol}://${localIP}:${port}`;
  }
  return `${protocol}://${host}`;
}

function getAccessUrls(port) {
  port = port || process.env.PORT || 3000;
  const urls = [];
  if (cachedPublicUrl) urls.push({ type: 'Public (worldwide)', url: cachedPublicUrl });
  urls.push({ type: 'Network (WiFi)', url: `http://${getLocalIP()}:${port}` });
  urls.push({ type: 'Hostname (WiFi)', url: `http://${getHostname()}:${port}` });
  urls.push({ type: 'Local', url: `http://localhost:${port}` });
  return urls;
}

module.exports = { getLocalIP, getHostname, getNgrokUrl, getPublicUrl, setNgrokUrl, getPublicCachedUrl: () => cachedPublicUrl, getAccessUrls };
