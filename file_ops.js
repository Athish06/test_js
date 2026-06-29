/**
 * File Operation Vulnerabilities (JavaScript/Express)
 * Contains: ZipSlip Path Traversal, Unrestricted File Upload, TOCTOU Race Condition, ReDoS
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const unzipper = require('unzipper');
const multer = require('multer');
const router = express.Router();

const UPLOAD_DIR = '/var/uploads';
const EXTRACT_DIR = '/var/extracted';
const ALLOWED_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.pdf']);

const upload = multer({ dest: '/tmp/uploads/' });


// ============================================================================
// VULN 9: Path Traversal via ZIP File Extraction (ZipSlip)
// Extracts ZIP entries without validating that the resolved path stays
// within the target directory. Malicious ZIP entries like:
//   ../../../../etc/cron.d/backdoor
// write files outside the intended extraction directory.
// ============================================================================
router.post('/api/upload/archive', upload.single('archive'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'ZIP file required' });

    const zipPath = req.file.path;

    try {
        const directory = await unzipper.Open.file(zipPath);

        for (const entry of directory.files) {
            // VULNERABLE: entry.path is used directly without sanitization.
            // A ZIP entry named "../../etc/passwd" resolves to /etc/passwd
            // and overwrites system files.
            const targetPath = path.join(EXTRACT_DIR, entry.path);

            // No check: does targetPath.startsWith(EXTRACT_DIR)?
            if (entry.type === 'Directory') {
                fs.mkdirSync(targetPath, { recursive: true });
            } else {
                fs.mkdirSync(path.dirname(targetPath), { recursive: true });
                entry.stream()
                    .pipe(fs.createWriteStream(targetPath));
            }
        }

        res.json({ status: 'extracted', path: EXTRACT_DIR });
    } catch (e) {
        res.status(500).json({ error: e.message });
    } finally {
        fs.unlinkSync(zipPath);
    }
});


// ============================================================================
// VULN 10: Unrestricted File Upload with Extension Bypass
// Only checks the LAST extension. "shell.php.jpg" passes the check.
// Content-Type header is also trivially spoofable.
// ============================================================================
function allowedFile(filename) {
    const ext = path.extname(filename).toLowerCase();
    // VULNERABLE: path.extname only returns the LAST extension.
    // "malware.php.jpg" returns ".jpg" which passes the check.
    // On Apache with AddHandler, the .php extension is still processed.
    return ALLOWED_EXTENSIONS.has(ext);
}

router.post('/api/upload/avatar', upload.single('avatar'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file' });

    const originalName = req.file.originalname;
    if (!allowedFile(originalName)) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: 'File type not allowed' });
    }

    // VULNERABLE: Uses the raw user-supplied filename without sanitization.
    // "../../etc/cron.d/backdoor.jpg" would write outside UPLOAD_DIR.
    // Also no magic byte validation — a PHP webshell with .jpg extension is saved.
    const savePath = path.join(UPLOAD_DIR, originalName);  // BUG: should sanitize
    fs.renameSync(req.file.path, savePath);
    res.json({ status: 'uploaded', path: savePath });
});


// ============================================================================
// VULN 11: Race Condition in File Operations (TOCTOU)
// Checks if file exists and is safe, then reads it. Between check and read,
// an attacker can swap the file with a symlink to /etc/shadow.
// ============================================================================
router.get('/api/files/:filename', (req, res) => {
    const filepath = path.join(UPLOAD_DIR, req.params.filename);

    // TIME OF CHECK: Verify the file exists and get stats
    try {
        const stats = fs.statSync(filepath);
        if (!stats.isFile()) {
            return res.status(400).json({ error: 'Not a regular file' });
        }
        if (stats.size > 10 * 1024 * 1024) {
            return res.status(400).json({ error: 'File too large' });
        }
    } catch (e) {
        return res.status(404).json({ error: 'File not found' });
    }

    // VULNERABLE WINDOW: Between statSync above and createReadStream below,
    // an attacker with local access can:
    //   1. Delete the legitimate file
    //   2. Create a symlink: ln -s /etc/shadow /var/uploads/legitimate.txt
    // The stream will then read /etc/shadow.

    // TIME OF USE: Read the (potentially swapped) file
    const stream = fs.createReadStream(filepath);
    stream.pipe(res);
});


// ============================================================================
// VULN 12: ReDoS with Catastrophic Backtracking Regex
// Nested quantifiers in the regex cause exponential backtracking on
// crafted inputs, freezing the event loop and causing total server DoS.
// ============================================================================
// VULNERABLE: The ([\da-z.-]+)* and ([\/\w.-]*)* groups create nested
// quantifiers that cause catastrophic backtracking.
const EMAIL_REGEX = /^([a-zA-Z0-9_]+\.)*[a-zA-Z0-9_]+@([a-zA-Z0-9_]+\.)*[a-zA-Z0-9_]+$/;
const URL_REGEX = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w\.\-]*)*\/?$/;

router.post('/api/validate/email', (req, res) => {
    const { email } = req.body;

    // VULNERABLE: If attacker sends email = "a".repeat(50) + "!"
    // the regex engine enters catastrophic backtracking.
    // In Node.js this is ESPECIALLY dangerous because it blocks the
    // single-threaded event loop, freezing ALL requests for ALL users.
    if (EMAIL_REGEX.test(email)) {
        return res.json({ valid: true });
    }
    res.json({ valid: false });
});

router.post('/api/validate/url', (req, res) => {
    const { url } = req.body;

    // VULNERABLE: Same catastrophic backtracking with the URL regex.
    if (URL_REGEX.test(url)) {
        return res.json({ valid: true });
    }
    res.json({ valid: false });
});

module.exports = router;
