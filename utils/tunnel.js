const http = require('http');

function getNgrokUrl(timeout = 3000) {
  return new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:4040/api/tunnels', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const tunnels = JSON.parse(data).tunnels || [];
          const httpsTunnel = tunnels.find(t => t.public_url && t.public_url.startsWith('https://'));
          resolve(httpsTunnel ? httpsTunnel.public_url : null);
        } catch {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(timeout, () => { req.destroy(); resolve(null); });
  });
}

function getTunnelUrl() {
  const envUrl = process.env.PUBLIC_URL;
  if (envUrl) return Promise.resolve(envUrl);
  return getNgrokUrl();
}

module.exports = { getNgrokUrl, getTunnelUrl };
