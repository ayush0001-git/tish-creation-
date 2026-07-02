/* Tiny static file server for the Tish Creations storefront.
 *
 * WHY THIS EXISTS
 * ---------------
 * Opening index.html directly via file:// works for browsing the storefront,
 * BUT browsers block cross-origin session cookies from file:// pages. That
 * means real account login / signup / order-history (which need a session
 * cookie set by the backend) silently fails in file:// mode.
 *
 * Serve the storefront over http:// instead — then the cookie flows work
 * correctly and you can test the full account flow against your backend.
 *
 * USAGE
 * -----
 *   node serve.js                # serves on http://localhost:8080
 *   node serve.js 9000           # serves on http://localhost:9000
 *
 * Then open http://localhost:8080/ in your browser.
 *
 * Make sure your backend's ALLOWED_ORIGINS includes the port you pick
 * (default in .env already includes http://localhost:8080).
 *
 * SECURITY
 * --------
 * - Path-traversal guard: every requested path is normalized and verified to
 *   stay inside the project root.
 * - Hidden files (anything starting with `.`) are blocked by default.
 * - Sensitive files (.env, server.js, package.json, node_modules/, etc.) are
 *   explicitly blocked even if they don't start with a dot.
 * - Security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
 *   are set on every response.
 * - Range requests are supported for video/large file streaming.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const PORT = parseInt(process.argv[2] || '8080', 10);
const ROOT = __dirname;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt':  'text/plain; charset=utf-8',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.otf':  'font/otf',
  '.eot':  'application/vnd.ms-fontobject',
  '.map':  'application/json',
  '.xml':  'application/xml; charset=utf-8',
  '.pdf':  'application/pdf',
  '.zip':  'application/zip',
  '.webmanifest': 'application/manifest+json',
};

// Files that must NEVER be served by the static server, even if they exist.
// (They are either secrets, server-side code, or dev-only.)
const BLOCKED = new Set([
  '.env', '.env.example', '.env.local', '.env.production',
  '_env.example',  // L4 fix: the actual filename used in this project (leading underscore, not a dotfile)
  'server.js', 'serve.js', 'package.json', 'package-lock.json',
  'yarn.lock', 'pnpm-lock.yaml',
  'CHANGES.md', 'CHANGES-v2.md', 'CHANGES-v3.md', 'CHANGES-v4.md', 'CHANGES-v5.md',
  'AUDIT-REPORT.md', 'RESEARCH-ecommerce-features.md',
  'README.md', 'worklog.md',
]);
const BLOCKED_DIRS = new Set(['node_modules', '.git', '.cache', '.vscode', '.idea']);

const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  'Cross-Origin-Resource-Policy': 'same-site',
};

const server = http.createServer((req, res) => {
  try {
    let urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
    if (urlPath === '/') urlPath = '/index.html';

    // Path-traversal guard: normalize and verify the resolved path stays
    // inside ROOT. path.normalize collapses ../ etc., then we check prefix.
    const filePath = path.normalize(path.join(ROOT, urlPath));
    if (!filePath.startsWith(ROOT + path.sep) && filePath !== ROOT) {
      res.writeHead(403, SEC_HEADERS); res.end('Forbidden'); return;
    }

    // Block hidden files (dotfiles) and explicitly-blocked files / dirs.
    const rel = path.relative(ROOT, filePath);
    const segments = rel.split(path.sep);
    if (segments.some(s => s.startsWith('.')) || segments.some(s => BLOCKED_DIRS.has(s))) {
      res.writeHead(404, SEC_HEADERS); res.end('Not found'); return;
    }
    if (BLOCKED.has(segments[segments.length - 1])) {
      res.writeHead(404, SEC_HEADERS); res.end('Not found'); return;
    }

    fs.stat(filePath, (err, stat) => {
      if (err || !stat.isFile()) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', ...SEC_HEADERS });
        res.end('404 Not Found: ' + urlPath);
        return;
      }
      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME[ext] || 'application/octet-stream';

      // Range support (for videos / large files).
      const range = req.headers.range;
      let start = 0, end = stat.size - 1, statusCode = 200;
      const headers = { ...SEC_HEADERS, 'Content-Type': contentType, 'Accept-Ranges': 'bytes' };
      if (range) {
        const m = /bytes=(\d*)-(\d*)/.exec(range);
        if (m) {
          start = m[1] ? parseInt(m[1], 10) : 0;
          end = m[2] ? parseInt(m[2], 10) : stat.size - 1;
          if (start > end || end >= stat.size) {
            res.writeHead(416, headers); res.end('Range Not Satisfiable'); return;
          }
          statusCode = 206;
          headers['Content-Range'] = `bytes ${start}-${end}/${stat.size}`;
        }
      }
      headers['Content-Length'] = end - start + 1;

      // Caching: immutable for hashed assets, must-revalidate for HTML.
      if (ext === '.html') {
        headers['Cache-Control'] = 'no-cache, must-revalidate';
      } else if (ext === '.json' || ext === '.xml' || ext === '.txt') {
        headers['Cache-Control'] = 'public, max-age=300';
      } else if (['.png','.jpg','.jpeg','.gif','.svg','.ico','.webp','.avif','.woff','.woff2','.ttf','.otf','.eot'].includes(ext)) {
        headers['Cache-Control'] = 'public, max-age=604800, immutable';
      } else {
        headers['Cache-Control'] = 'public, max-age=3600';
      }

      // gzip/deflate if the client supports it and the file is large enough.
      const acceptEnc = req.headers['accept-encoding'] || '';
      const useGzip = /gzip/.test(acceptEnc) && stat.size > 1024 &&
        /\.(html|js|css|json|xml|txt|svg)$/.test(ext);
      if (useGzip) {
        delete headers['Content-Length'];
        headers['Content-Encoding'] = 'gzip';
        res.writeHead(statusCode, headers);
        fs.createReadStream(filePath, { start, end }).pipe(zlib.createGzip()).pipe(res);
      } else {
        res.writeHead(statusCode, headers);
        fs.createReadStream(filePath, { start, end }).pipe(res);
      }
    });
  } catch (e) {
    res.writeHead(500, SEC_HEADERS); res.end('Server error: ' + (e && e.message));
  }
});

server.listen(PORT, () => {
  console.log(`\n🌸 Tish Creations storefront → http://localhost:${PORT}/`);
  console.log(`   Serving: ${ROOT}`);
  console.log(`   Security: path-traversal guard, dotfile block, security headers, gzip`);
  console.log(`   Press Ctrl+C to stop.\n`);
});
