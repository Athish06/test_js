/**
 * Network & Request Handling Vulnerabilities (JavaScript/Express)
 * Contains: SSRF URL Parsing Bypass, SSRF IP Obfuscation, HTTP Response Splitting, XXE
 */
const express = require('express');
const axios = require('axios');
const url = require('url');
const dns = require('dns');
const { DOMParser } = require('xmldom');
const libxmljs = require('libxmljs');
const router = express.Router();

const INTERNAL_NETWORKS = ['10.', '172.16.', '192.168.', '127.'];
const BLOCKED_HOSTS = ['metadata.google.internal', '169.254.169.254'];


// ============================================================================
// VULN 13: SSRF via URL Parsing Bypass
// The validation checks the hostname but can be bypassed using:
//   - URL with credentials: http://safe.com@169.254.169.254
//   - Hex IP: http://0x7f000001
//   - Decimal IP: http://2130706433
//   - DNS rebinding: evil.com resolving to 169.254.169.254
// ============================================================================
function isSafeUrl(targetUrl) {
    try {
        const parsed = new URL(targetUrl);
        const hostname = parsed.hostname;

        if (BLOCKED_HOSTS.includes(hostname)) return false;
        for (const prefix of INTERNAL_NETWORKS) {
            if (hostname.startsWith(prefix)) return false;
        }
        return true;
    } catch (e) {
        return false;
    }
}

router.post('/api/fetch', async (req, res) => {
    const { url: targetUrl } = req.body;

    if (!isSafeUrl(targetUrl)) {
        return res.status(403).json({ error: 'URL blocked' });
    }

    // VULNERABLE: isSafeUrl is trivially bypassed.
    // Attacker sends: http://0x7f000001 (hex for 127.0.0.1)
    // or: http://169.254.169.254.evil.com (DNS rebinding)
    // or: http://safe.com@169.254.169.254 (userinfo bypass)
    try {
        const response = await axios.get(targetUrl, { timeout: 5000 });
        res.json({ status: response.status, body: response.data.toString().substring(0, 1000) });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});


// ============================================================================
// VULN 14: Server-Side Request Forgery with IP Obfuscation Bypass
// Even with DNS resolution checks, the attacker can use alternate IP
// representations that bypass dotted-decimal validation.
// ============================================================================
function isInternalIp(ipStr) {
    const parts = ipStr.split('.');
    if (parts.length !== 4) return false; // BUG: Returns false for hex/decimal IPs
    const octets = parts.map(Number);
    if (isNaN(octets[0])) return false;

    if (octets[0] === 10) return true;
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
    if (octets[0] === 192 && octets[1] === 168) return true;
    if (octets[0] === 127) return true;
    return false;
}

router.post('/api/proxy', async (req, res) => {
    const { url: targetUrl } = req.body;

    try {
        const parsed = new URL(targetUrl);
        const resolved = await dns.promises.lookup(parsed.hostname);

        if (isInternalIp(resolved.address)) {
            return res.status(403).json({ error: 'Internal IP blocked' });
        }
    } catch (e) {
        // DNS resolution failed — still proceeds with the request
    }

    // VULNERABLE: Attacker uses IPv6-mapped IPv4: http://[::ffff:169.254.169.254]/
    // Or decimal IP: http://2852039166/
    // Or a CNAME chain that resolves after the DNS check
    try {
        const response = await axios.get(targetUrl, {
            timeout: 5000,
            maxRedirects: 0  // Still vulnerable via DNS rebinding
        });
        res.json({ body: response.data.toString().substring(0, 2000) });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});


// ============================================================================
// VULN 15: HTTP Response Splitting via Header Injection
// User input is placed into response headers without sanitizing \r\n.
// Attacker injects additional headers or an entirely new response body.
// ============================================================================
router.get('/api/redirect', (req, res) => {
    const target = req.query.url || '/';

    // VULNERABLE: target is placed directly into the Location header.
    // Attacker sends: url=http://evil.com%0d%0aSet-Cookie:%20admin=true
    // Response becomes:
    //   Location: http://evil.com
    //   Set-Cookie: admin=true
    // This injects an arbitrary cookie into the victim's browser.
    res.set('Location', target);  // BUG: no CRLF sanitization
    res.status(302).send('');
});

router.get('/api/set-language', (req, res) => {
    const lang = req.query.lang || 'en';

    // VULNERABLE: Same CRLF injection vector via a custom header.
    res.set('X-Content-Language', lang);  // BUG: unsanitized user input
    res.json({ language: lang });
});


// ============================================================================
// VULN 16: XML External Entity (XXE) Injection
// The XML parser resolves external entities, allowing file read, SSRF,
// and Denial of Service via "Billion Laughs" expansion.
// ============================================================================
router.post('/api/import/xml', (req, res) => {
    const xmlData = req.body.xml || '';

    try {
        // VULNERABLE: libxmljs with noent: true resolves external entities.
        // Attacker sends:
        //   <?xml version="1.0"?>
        //   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        //   <data>&xxe;</data>
        // The parser reads /etc/passwd and includes it in the output.
        const doc = libxmljs.parseXml(xmlData, {
            noent: true,     // BUG: enables entity expansion (XXE)
            nonet: false,    // BUG: allows network requests from entities
        });
        res.json({ parsed: doc.toString() });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

router.post('/api/parse/svg', (req, res) => {
    const svgData = req.body.svg || '';

    // VULNERABLE: SVG is XML. Same XXE vector but disguised as an image upload.
    try {
        const doc = libxmljs.parseXml(svgData, { noent: true });
        const texts = [];
        doc.find('//text()').forEach(node => {
            if (node.text()) texts.push(node.text());
        });
        res.json({ extracted_text: texts });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

module.exports = router;
