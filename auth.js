/**
 * Authentication & Authorization Vulnerabilities (JavaScript/Express)
 * Contains: JWT Algorithm Confusion, Timing Attack, IDOR with Encoded IDs, Mass Assignment
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const router = express.Router();

const PUBLIC_KEY = fs.readFileSync('public.pem', 'utf-8');
const PRIVATE_KEY = fs.readFileSync('private.pem', 'utf-8');
const SECRET_KEY = 'supersecretkey123';
const usersDb = {};

// ============================================================================
// VULN 1: JWT Algorithm Confusion Attack
// The server signs with RS256 (asymmetric) but jwt.verify() doesn't restrict
// the accepted algorithms. An attacker forges a token using HS256 with the
// PUBLIC key as the HMAC secret (the public key is publicly available).
// ============================================================================
function createToken(userId, role) {
    return jwt.sign({ user_id: userId, role: role }, PRIVATE_KEY, { algorithm: 'RS256' });
}

function verifyToken(token) {
    try {
        // VULNERABLE: No algorithms restriction. jwt.verify() will accept ANY
        // algorithm the token header claims. Attacker creates a token with:
        //   header: {"alg": "HS256"}
        //   payload: {"user_id": "1", "role": "admin"}
        // and signs it with HMAC-SHA256 using the PUBLIC_KEY as the secret.
        // Since jwt.verify() sees alg=HS256, it treats PUBLIC_KEY as an HMAC secret
        // and the signature is valid.
        return jwt.verify(token, PUBLIC_KEY);  // BUG: no { algorithms: ['RS256'] }
    } catch (e) {
        return null;
    }
}

router.get('/admin/dashboard', (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const claims = verifyToken(token);
    if (!claims || claims.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    res.json({ secret_data: 'all_user_emails_and_passwords' });
});


// ============================================================================
// VULN 2: Timing Attack in HMAC Comparison
// Uses === (string equality) instead of crypto.timingSafeEqual().
// An attacker brute-forces the signature byte-by-byte by measuring response times.
// ============================================================================
function generateSignature(payload, secret) {
    return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

router.post('/api/webhook', (req, res) => {
    const payload = JSON.stringify(req.body);
    const receivedSig = req.headers['x-signature'] || '';
    const expectedSig = generateSignature(payload, SECRET_KEY);

    // VULNERABLE: String comparison === returns early on the first mismatched byte.
    // Each additional correct byte adds measurable nanoseconds to the response.
    // An attacker can determine the full signature one character at a time.
    if (receivedSig === expectedSig) {  // BUG: should use crypto.timingSafeEqual()
        processWebhook(req.body);
        return res.json({ status: 'ok' });
    }
    res.status(401).json({ error: 'invalid signature' });
});

function processWebhook(data) { /* ... */ }


// ============================================================================
// VULN 3: Insecure Direct Object Reference with Encoded IDs
// User IDs are "obfuscated" with base64, but base64 is encoding, not encryption.
// An attacker trivially decodes, modifies, and re-encodes the ID.
// ============================================================================
router.get('/api/profile/:encodedId', (req, res) => {
    let userId;
    try {
        // VULNERABLE: base64 decoding provides zero security.
        // "MTIz" decodes to "123". Attacker changes to "124", re-encodes to "MTI0",
        // and accesses another user's profile.
        userId = Buffer.from(req.params.encodedId, 'base64').toString('utf-8');
    } catch (e) {
        return res.status(400).json({ error: 'Invalid ID' });
    }

    const user = usersDb[userId];
    if (!user) return res.status(404).json({ error: 'Not found' });

    // No ownership check: does the CURRENT authenticated user own this profile?
    res.json(user);
});

router.delete('/api/profile/:encodedId', (req, res) => {
    const userId = Buffer.from(req.params.encodedId, 'base64').toString('utf-8');
    // VULNERABLE: Any authenticated user can delete ANY other user's profile.
    if (usersDb[userId]) {
        delete usersDb[userId];
    }
    res.json({ status: 'deleted' });
});


// ============================================================================
// VULN 4: Mass Assignment via Object.assign Without Field Filtering
// The update endpoint blindly merges all user-supplied fields into the user
// object, allowing privilege escalation by setting role/isAdmin fields.
// ============================================================================
class User {
    constructor(username, email) {
        this.username = username;
        this.email = email;
        this.role = 'user';
        this.isAdmin = false;
        this.isVerified = false;
    }
}

router.put('/api/user/update', (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const claims = verifyToken(token);
    if (!claims) return res.status(401).json({ error: 'Unauthorized' });

    const user = usersDb[claims.user_id];
    if (!user) return res.status(404).json({ error: 'User not found' });

    // VULNERABLE: Object.assign merges ALL fields from the request body.
    // Attacker sends: {"email": "new@email.com", "role": "admin", "isAdmin": true}
    // All three fields are applied to the user object, including role escalation.
    Object.assign(user, req.body);  // BUG: no allowlist filtering
    res.json({ status: 'updated' });
});

module.exports = router;
