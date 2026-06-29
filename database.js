/**
 * Database & Data Manipulation Vulnerabilities (JavaScript/Express)
 * Contains: Second-Order SQLi, NoSQL Injection (MongoDB), Business Logic Flaw, Prototype Pollution
 */
const express = require('express');
const mysql = require('mysql2/promise');
const mongoose = require('mongoose');
const router = express.Router();

let db;
mysql.createConnection({ host: 'localhost', user: 'root', database: 'vuln_app' })
    .then(conn => { db = conn; });

const UserModel = mongoose.model('User', new mongoose.Schema({
    username: String, password: String, email: String, role: String
}));
const ProductModel = mongoose.model('Product', new mongoose.Schema({
    name: String, price: Number, quantity: Number
}));


// ============================================================================
// VULN 5: Second-Order SQL Injection
// Data is stored safely via parameterized query, but retrieved and used
// unsafely in a completely different admin endpoint days/weeks later.
// ============================================================================
router.post('/api/register', async (req, res) => {
    const { username, bio } = req.body;

    // SAFE: Parameterized query. The injection payload is stored inertly.
    await db.execute('INSERT INTO users (username, bio) VALUES (?, ?)', [username, bio]);
    res.json({ status: 'registered' });
});

router.get('/api/admin/user_report', async (req, res) => {
    // Step 1: Safely fetch all usernames
    const [rows] = await db.execute('SELECT username FROM users');

    const results = [];
    for (const row of rows) {
        // VULNERABLE: The username was stored safely, but is now concatenated
        // directly into a raw SQL query. If a user registered with username:
        //   admin' UNION SELECT password FROM credentials --
        // this query executes the attacker's injected SQL.
        const query = `SELECT * FROM users WHERE username = '${row.username}'`;
        const [data] = await db.query(query);
        results.push(...data);
    }
    res.json({ report: results });
});


// ============================================================================
// VULN 6: NoSQL Injection via MongoDB Operator Injection
// Raw request body JSON is passed directly into a MongoDB query.
// Attacker injects query operators like $gt, $ne, $regex.
// ============================================================================
router.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // VULNERABLE: If attacker sends:
    //   {"username": "admin", "password": {"$ne": ""}}
    // MongoDB interprets {"$ne": ""} as "password not equal to empty string",
    // which matches ANY non-empty password, bypassing authentication.
    const user = await UserModel.findOne({ username, password });

    if (user) {
        return res.json({ status: 'logged_in', user: user._id });
    }
    res.status(401).json({ error: 'Invalid credentials' });
});

router.get('/api/search', async (req, res) => {
    let searchFilter = req.query.q || '';

    // VULNERABLE: Attacker sends q={"$regex":".*"} as a JSON string.
    // The app parses it and passes the object directly to MongoDB.
    try {
        searchFilter = JSON.parse(searchFilter);
    } catch (e) {
        // stays as a string — fine for normal usage
    }

    const results = await UserModel.find({ username: searchFilter });
    res.json({ results });
});


// ============================================================================
// VULN 7: Business Logic Flaw - Negative Quantity/Price Exploitation
// No validation that quantity is positive. Negative quantity = refund.
// ============================================================================
router.post('/api/checkout', async (req, res) => {
    const { items } = req.body;
    let total = 0;

    for (const item of items) {
        const product = await ProductModel.findById(item.product_id);
        if (!product) continue;

        const quantity = item.quantity; // Attacker sends -10

        // VULNERABLE: No check that quantity > 0.
        // price=50, quantity=-10 → lineTotal = -500 → company PAYS the attacker.
        const lineTotal = product.price * quantity;
        total += lineTotal;

        // Negative quantity INCREASES stock instead of decreasing it
        await ProductModel.updateOne(
            { _id: item.product_id },
            { $inc: { quantity: -quantity } }
        );
    }

    chargeCustomer(total); // Negative total = refund
    res.json({ total_charged: total });
});

function chargeCustomer(amount) { /* Stripe API call — negative = refund */ }


// ============================================================================
// VULN 8: Prototype Pollution
// Recursive object merge without __proto__ / constructor / prototype filtering.
// Attacker can pollute Object.prototype, affecting ALL objects in the app.
// ============================================================================
function deepMerge(target, source) {
    for (const key in source) {
        // VULNERABLE: No check for __proto__, constructor, or prototype.
        // Attacker sends: {"__proto__": {"isAdmin": true}}
        // This sets Object.prototype.isAdmin = true, meaning EVERY object
        // in the application now has isAdmin === true.
        if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

const appConfig = { debug: false, adminEnabled: false };

router.patch('/api/admin/config', (req, res) => {
    // VULNERABLE: Merges raw user input into the config object.
    // Attacker sends: {"__proto__": {"isAdmin": true, "role": "admin"}}
    // Now every object in the Node.js process has .isAdmin === true
    deepMerge(appConfig, req.body);
    res.json({ status: 'config updated', debug: appConfig.debug });
});

module.exports = router;
