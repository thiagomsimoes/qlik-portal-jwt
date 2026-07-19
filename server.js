require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const privateKeyPath = path.join(__dirname, 'private.pem');
if (!fs.existsSync(privateKeyPath)) {
    console.error('Missing private.pem in project root. Generate it with OpenSSL or Node and place it here.');
    process.exit(1);
}

const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

const requiredEnv = [
    'APP_SECRET',
    'QLIK_TENANT_URL',
    'QLIK_JWT_ISSUER',
    'QLIK_JWT_KEY_ID',
    'QLIK_WEB_INTEGRATION_ID',
    'QLIK_APP_ID'
];

const missingEnv = requiredEnv.filter((name) => !process.env[name]);
if (missingEnv.length) {
    console.error('Missing required environment variables:', missingEnv.join(', '));
    process.exit(1);
}

function checkAuth(req, res, next) {
    const token = req.cookies.app_session_token;
    if (!token) {
        return res.status(401).redirect('/login.html');
    }

    try {
        const decoded = jwt.verify(token, process.env.APP_SECRET);
        req.user = decoded;
        return next();
    } catch (err) {
        res.clearCookie('app_session_token');
        return res.status(401).redirect('/login.html');
    }
}

function mintQlikToken(user) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        jti: Math.random().toString(36).substring(2),
        iss: process.env.QLIK_JWT_ISSUER,
        sub: user.email,
        subType: 'user',
        aud: 'qlik.api/login/jwt-session',
        nbf: now,
        exp: now + 60 * 5,
        name: user.name,
        email: user.email,
        email_verified: true,
        groups: user.groups || []
    };

    return jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        keyid: process.env.QLIK_JWT_KEY_ID
    });
}

function mintQlikApiToken(user) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        jti: Math.random().toString(36).substring(2),
        iss: process.env.QLIK_JWT_ISSUER,
        sub: user.email,
        subType: 'user',
        aud: 'qlik.api/login-jwt',
        nbf: now,
        exp: now + 60 * 5,
        name: user.name,
        email: user.email,
        email_verified: true,
        groups: user.groups || []
    };

    return jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        keyid: process.env.QLIK_JWT_KEY_ID
    });
}

async function fetchQlikUserGroups(user) {
    const tenantUrl = process.env.QLIK_TENANT_URL.replace(/\/$/, '');
    const token = mintQlikApiToken(user);
    const response = await fetch(`${tenantUrl}/api/v1/users/me`, {
        method: 'GET',
        headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    });

    const text = await response.text();
    if (!response.ok) {
        throw new Error(`Qlik user info failed: ${response.status} ${text}`);
    }

    let json;
    try {
        json = JSON.parse(text);
    } catch (err) {
        throw new Error(`Invalid JSON from Qlik user info: ${err.message}`);
    }

    const userData = json.data || json;
    console.log('[qlik] user response received:', userData);

    if (!userData) {
        return {
            id: user.id,
            name: user.name,
            email: user.email,
            groups: []
        };
    }

    const groups = [];
    const assignedGroups = Array.isArray(userData.assignedGroups)
        ? userData.assignedGroups
        : Array.isArray(userData.groups)
            ? userData.groups
            : [];

    assignedGroups.forEach((group) => {
        if (group.name) groups.push(group.name);
        else if (group.id) groups.push(group.id);
        else if (group.title) groups.push(group.title);
    });

    const fullName = userData.name || userData.displayName || userData.fullName || user.name || '';
    const nameParts = fullName.trim().split(/\s+/).filter(Boolean);
    const firstName = nameParts[0] || '';
    const lastName = nameParts.slice(1).join(' ') || '';
    const profile = userData.profile || userData.userProfile || userData.details || userData.attributes || {};
    const jobTitle = userData.jobTitle || userData.job_title || profile.jobTitle || profile.job_title || profile.jobtitle || userData.title || userData.position || userData.role || profile.title || profile.position || profile.role || '';
    const company = userData.company || userData.companyName || userData.company_name || profile.company || profile.companyName || profile.company_name || userData.organization || userData.organisation || userData.org || profile.organization || profile.organisation || profile.org || '';

    return {
        id: userData.id || userData.userId || userData.uid || userData.user_id || user.id,
        name: fullName || user.name,
        email: userData.email || userData.userEmail || user.email,
        firstName,
        lastName,
        jobTitle,
        company,
        groups
    };
}

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Credentials required. <a href="/login.html">Try again</a>');
    }

    const cleanUser = username.trim().toLowerCase();
    let validatedUser = null;

    if (cleanUser === 'thiagomsimoes@poli.ufrj.br' && password === '1234') {
        const baseUser = {
            id: 'usr_thiago_ufrj',
            name: 'Thiago M. Simões',
            email: cleanUser,
            groups: []
        };

        try {
            const qlikUserData = await fetchQlikUserGroups(baseUser);
            validatedUser = {
                ...baseUser,
                id: qlikUserData.id || baseUser.id,
                name: qlikUserData.name || baseUser.name,
                email: qlikUserData.email || baseUser.email,
                firstName: qlikUserData.firstName || '',
                lastName: qlikUserData.lastName || '',
                jobTitle: qlikUserData.jobTitle || '',
                company: qlikUserData.company || '',
                groups: qlikUserData.groups || []
            };
        } catch (err) {
            console.warn(`[auth] could not enrich user from Qlik:`, err.message);
            validatedUser = baseUser;
        }
    }

    if (!validatedUser) {
        return res.status(401).send('Invalid credentials. <a href="/login.html">Try again</a>');
    }

    const appSessionToken = jwt.sign(validatedUser, process.env.APP_SECRET, { expiresIn: '2h' });
    res.cookie('app_session_token', appSessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    });

    return res.redirect('/dashboard.html');
});

app.get('/auth/logout', (req, res) => {
    res.clearCookie('app_session_token');
    res.redirect('/login.html');
});

app.get('/api/qlik/token', checkAuth, (req, res) => {
    try {
        const token = mintQlikToken(req.user);
        console.log(`[auth] /api/qlik/token for ${req.user.email}`);
        res.json({ token });
    } catch (err) {
        console.error('Failed to mint Qlik JWT:', err);
        res.status(500).json({ error: 'Failed to mint token' });
    }
});

app.get('/api/config', checkAuth, (req, res) => {
    const payload = {
        host: process.env.QLIK_TENANT_URL.replace(/\/$/, ''),
        webIntegrationId: process.env.QLIK_WEB_INTEGRATION_ID,
        appId: process.env.QLIK_APP_ID,
        targetAppId: process.env.QLIK_APP_ID,
        targetObjectId: process.env.QLIK_OBJECT_ID || process.env.QLIK_TABLE_ID || '',
        userName: req.user.name,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        jobTitle: req.user.jobTitle,
        company: req.user.company,
        userGroups: req.user.groups || []
    };

    console.log(`[auth] /api/config for ${req.user.email}`, payload);
    res.json(payload);
});

app.get('/dashboard.html', checkAuth);
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.redirect('/login.html'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Portal de aplicações ativo em http://localhost:${PORT}`);
});


/*teste*/