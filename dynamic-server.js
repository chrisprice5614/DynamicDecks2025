require("dotenv").config() // Makes it so we can access .env file
const jwt = require("jsonwebtoken")//npm install jsonwebtoken dotenv
const path = require('path');
const express = require("express")//npm install express
const db = require("better-sqlite3")("database.db") //npm install better-sqlite3
const body_parser = require("body-parser")
const axios = require('axios');
const requestIp = require('request-ip');
const bcrypt = require("bcryptjs") //npm install bcryptjs
const cookieParser = require("cookie-parser")//npm install cookie-parser
const nodemailer = require("nodemailer")
const multer = require("multer")
const sharp = require('sharp');
const fs = require("fs");
const marked = require('marked');
const puppeteer = require('puppeteer');
// JWT secret fallback for local/dev to prevent crashes when .env missing
const JWT_SECRET = process.env.JWTSECRET || 'local-dev-secret';
const fileStorageEngine = multer.diskStorage({
    
    destination: (req, file, cb) => {
          
        if(file.mimetype == "video/mp4")
        {
            cb(null, "./public/video")
        }
        else
        {
            cb(null, "./public/img/gallery")
        }
    },
    filename: (req, file, cb) => {
        
        

            if(file.mimetype == "video/mp4")
            {
                console.log(req.params.id)
                cb(null, req.params.id + ".mp4")
            }
            else
            {
                
                const uniqueSuffix = Date.now() + "-" + Math.round(Math.random()*1e9);
                cb(null, uniqueSuffix + path.extname(file.originalname))

                
            }
    }
    });
const upload = multer({storage: fileStorageEngine, fileFilter: (req, file, cb) => {
    const mime = file.mimetype;
    const allowedTypes = [
      'video/mp4',
      'image/jpeg',
      'image/png',
    ];

    if (allowedTypes.includes(mime)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type'), false);
    }
}})

const fileSizeLimiter = (req, res, next) => {
    const file = req.file;
    if (!file) return next();
  
    const mime = file.mimetype;
    const size = file.size;
  
    const limits = {
      'image/jpeg': 12 * 1024 * 1024,        // 3 MB
      'image/png': 12 * 1024 * 1024,
      'video/mp4': 12 * 1024 * 1024,       // 12 MB (mp3)
    };
  
    const limit = limits[mime];
    if (limit && size > limit) {
      return res.status(400).json({ error: `File too large. Limit is ${limit / (1024 * 1024)}MB.` });
    }
  
    next();
};

const app = express()
app.use(express.json())

app.set("view engine", "ejs")
app.use(requestIp.mw());
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({extended: false}))// This makes it so we can easily access requests
app.use(express.static("public")) //Using public folder
app.use(express.static('/public'));
app.use(body_parser.json())
app.use(cookieParser())

//mailing function
async function sendEmail(to, subject, html) {
    let transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
            user: process.env.MAILNAME,
            pass: process.env.MAILSECRET
        },
        tls: {
            rejectUnauthorized: false
        }
    });


    let info = await transporter.sendMail({
        from: '"Chris Price Music" <info@chrispricemusic.net>',
        to: to,
        subject: subject,
        html: html

    })

}

db.pragma("journal_mode = WAL") //Makes it faster

const createTables = db.transaction(() => {
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sessionId STRING NOT NULL UNIQUE,
        visits STRING,
        converted BOOL,
        date INTEGER NOT NULL
        )
        `
    ).run()

    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS pages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        page STRING,
        hero STRING,
        header STRING,
        content STRING
        )
        `
    ).run()

    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS login (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING,
        key STRING
        )
        `
    ).run()

    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS gallery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path STRING,
        description STRING,
        pergola BOOL,
        cover BOOL,
        privacywall BOOL,
        decks BOOL,
        stairs BOOL,
        railing BOOL,
        lighting BOOL
        )
        `
    ).run()

    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS blogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        page STRING,
        active BOOL,
        slug STRING,
        hero STRING,
        content STRING,
        header STRING
        )
        `
    ).run()

})

createTables();

function slugify(title) {
  return title
    .toLowerCase()
    .replace(/\s+/g, '-')           // replace spaces with dashes
    .replace(/[^\w\-]+/g, '')       // remove special characters
    .replace(/\-\-+/g, '-')         // collapse multiple dashes
    .replace(/^-+|-+$/g, '');       // trim dashes from start/end
}

// Add lazy-loading and async decode to content images (faster perceived load, same visual quality)
function enhanceContentHtml(html) {
    if (!html || typeof html !== 'string') return html;
    return html.replace(/<img\s+([^>]+)>/gi, (match, attrs) => {
        if (/class\s*=\s*["'][^"']*no-lazy/i.test(attrs)) return match;
        let a = attrs.trim();
        if (!/\bloading\s*=/i.test(a)) a += ' loading="lazy"';
        if (!/\bdecoding\s*=/i.test(a)) a += ' decoding="async"';
        if (!/\bfetchpriority\s*=/i.test(a)) a += ' fetchpriority="low"';
        return `<img ${a}>`;
    });
}


// Bot user-agent detection: skip session tracking for crawlers
const BOT_PATTERN = /bot|crawler|spider|scraper|curl|wget|python|java|libwww|httpclient|Go-http|Baiduspider|YandexBot|SemrushBot|AhrefsBot|MJ12bot|DotBot|facebookexternalhit|Googlebot|Bingbot|Slurp|DuckDuckBot|archive\.org_bot|ia_archiver|Sogou|Exabot|Alexa|Voila|uptimerobot|pingdom|monitor/i;
function isBot(req) {
    const ua = req.headers['user-agent'] || '';
    return BOT_PATTERN.test(ua);
}

//Middleware
app.use(function (req, res, next) {
    res.locals.errors = [] //Setting the errors to nothings
    const ip = req.clientIp; //Getting the client ip for session purposes

    //Session id - ip+date encrypted so no one can steal it :)
    //Visits - Array of page visits, [{page, timeStamp}]
    //Converted - Converted to form submission

    try {
        const decoded = jwt.verify(req.cookies.login, JWT_SECRET)
        req.user = decoded
    } catch(err){
        req.user = false
    }

    res.locals.user = req.user;

    if (!isBot(req)) {
        try {
            const decoded = jwt.verify(req.cookies.session, JWT_SECRET)
            req.session = decoded
        } catch(err) {
            let salt = bcrypt.genSaltSync(10)
            let sessionId = bcrypt.hashSync(ip + Date.now().toString(), salt)
            req.session = {exp: Math.floor(Date.now() / 1000) + (60*60*0.5), sessionId, visits: [], converted: false};
            const ourTokenValue = jwt.sign(req.session, JWT_SECRET)

            res.cookie("session",ourTokenValue, {
                httpOnly: true,
                secure: true,
                sameSite: "strict",
                maxAge: 1000 * 60 * 60 * 0.5
            })

            const sessionStatement = db.prepare("INSERT into sessions (sessionId, date) VALUES (? , ?)")
            sessionStatement.run(req.session.sessionId, Date.now())
        }

        // Record visits robustly (cap at 50 to avoid oversized cookies)
        try {
            if (req.session && !Array.isArray(req.session.visits)) req.session.visits = [];
            if (req.session && req.session.visits.length < 50) {
                req.session.visits.push({ url: req.originalUrl, time: Date.now() });
                const sessionStatement = db.prepare("UPDATE sessions set visits = ? WHERE sessionId = ?");
                sessionStatement.run(JSON.stringify(req.session.visits), req.session.sessionId);
                req.session = { exp: Math.floor(Date.now() / 1000) + (60 * 60 * 0.5), sessionId: req.session.sessionId, visits: req.session.visits, converted: req.session.converted };
                const ourTokenValue = jwt.sign(req.session, JWT_SECRET);
                res.cookie("session", ourTokenValue, {
                    httpOnly: true,
                    secure: true,
                    sameSite: "strict",
                    maxAge: 1000 * 60 * 60 * 0.5
                });
            }
        } catch (e) {
            // non-fatal; continue
        }
    } else {
        req.session = { visits: [], converted: false, sessionId: null };
    }

    //console.log(req.session)
    
    next()
})

app.get("/thanks", (req,res) => {
    const sessionStatement = db.prepare("UPDATE sessions set converted = 1 WHERE sessionId = ?")
    sessionStatement.run(req.session.sessionId)

    return res.render("thanks")
})

// Simple cookie-based auth for reports
function mustHaveReportAuth(req, res, next) {
    if (req.cookies.reportAuth === "1") return next();
    return res.redirect("/report-login");
}

// Build metrics for the report
function buildReportMetrics() {
    const sessionsStmt = db.prepare("SELECT * FROM sessions ORDER BY date ASC");
    const sessions = sessionsStmt.all();

    const totalSessions = sessions.length;
    const convertedSessions = sessions.filter(s => s.converted === 1).length;

    const now = Date.now();
    const DAYS = (n) => now - n * 24 * 60 * 60 * 1000;
    const inRange = (ms, startMs) => ms >= startMs && ms <= now;
    const monthStart = DAYS(30);

    const last7 = sessions.filter(s => inRange(s.date, DAYS(7))).length;
    const last30 = sessions.filter(s => inRange(s.date, DAYS(30))).length;
    const last90 = sessions.filter(s => inRange(s.date, DAYS(90))).length;

    const conv7 = sessions.filter(s => s.converted === 1 && inRange(s.date, DAYS(7))).length;
    const conv30 = sessions.filter(s => s.converted === 1 && inRange(s.date, DAYS(30))).length;
    const conv90 = sessions.filter(s => s.converted === 1 && inRange(s.date, DAYS(90))).length;

    // Aggregate page visits from stored visits JSON, if present
    const pageCounts = {};
    const entryCounts = {};
    const exitCounts = {};
    let sessionsWithContact = 0, sessionsWithRequest = 0, sessionsWithCareer = 0;
    // Monthly breakdowns
    const pageCountsMonth = {};
    const entryCountsMonth = {};
    const exitCountsMonth = {};
    let sessionsWithContactMonth = 0, sessionsWithRequestMonth = 0, sessionsWithCareerMonth = 0;
    let totalPagesAll = 0, totalPagesMonth = 0;
    let bouncesAll = 0, bouncesMonth = 0;
    for (const s of sessions) {
        if (s.visits) {
            try {
                const arr = JSON.parse(s.visits);
                if (Array.isArray(arr)) {
                    // entry/exit pages
                    const first = arr[0] && arr[0].url ? arr[0].url : null;
                    const last = arr[arr.length - 1] && arr[arr.length - 1].url ? arr[arr.length - 1].url : null;
                    if (first) entryCounts[first] = (entryCounts[first] || 0) + 1;
                    if (last) exitCounts[last] = (exitCounts[last] || 0) + 1;

                    for (const v of arr) {
                        const url = (v && v.url) ? v.url : null;
                        if (!url) continue;
                        pageCounts[url] = (pageCounts[url] || 0) + 1;
                        if (url.startsWith('/contact')) sessionsWithContact++;
                        if (url.startsWith('/request')) sessionsWithRequest++;
                        if (url.startsWith('/career')) sessionsWithCareer++;
                    }

                    // monthly
                    if (inRange(s.date, monthStart)) {
                        const mFirst = first;
                        const mLast = last;
                        if (mFirst) entryCountsMonth[mFirst] = (entryCountsMonth[mFirst] || 0) + 1;
                        if (mLast) exitCountsMonth[mLast] = (exitCountsMonth[mLast] || 0) + 1;

                        for (const v of arr) {
                            const url = (v && v.url) ? v.url : null;
                            if (!url) continue;
                            pageCountsMonth[url] = (pageCountsMonth[url] || 0) + 1;
                            if (url.startsWith('/contact')) sessionsWithContactMonth++;
                            if (url.startsWith('/request')) sessionsWithRequestMonth++;
                            if (url.startsWith('/career')) sessionsWithCareerMonth++;
                        }
                        totalPagesMonth += arr.length;
                        if (arr.length <= 1) bouncesMonth++;
                    }

                    totalPagesAll += arr.length;
                    if (arr.length <= 1) bouncesAll++;
                }
            } catch(err) {
                // ignore malformed visits
            }
        }
    }

    const topPages = Object.entries(pageCounts)
        .sort((a,b) => b[1]-a[1])
        .slice(0, 20)
        .map(([url, count]) => ({url, count}));

    const topEntryPages = Object.entries(entryCounts)
        .sort((a,b) => b[1]-a[1])
        .slice(0, 15)
        .map(([url, count]) => ({url, count}));

    const topExitPages = Object.entries(exitCounts)
        .sort((a,b) => b[1]-a[1])
        .slice(0, 15)
        .map(([url, count]) => ({url, count}));

    const topPagesMonth = Object.entries(pageCountsMonth)
        .sort((a,b) => b[1]-a[1])
        .slice(0, 20)
        .map(([url, count]) => ({url, count}));

    const topEntryPagesMonth = Object.entries(entryCountsMonth)
        .sort((a,b) => b[1]-a[1])
        .slice(0, 15)
        .map(([url, count]) => ({url, count}));

    const topExitPagesMonth = Object.entries(exitCountsMonth)
        .sort((a,b) => b[1]-a[1])
        .slice(0, 15)
        .map(([url, count]) => ({url, count}));

    // Keyword extraction from pages and blogs
    const pageRows = db.prepare("SELECT page, header, content, hero FROM pages").all();
    const blogRowsFull = db.prepare("SELECT id, page, active, slug, hero, content, header FROM blogs").all();
    const blogRows = blogRowsFull.filter(b => b.active === 1);

    const textBlob = [...pageRows, ...blogRows]
        .map(r => `${r.header || ''} ${r.content || ''}`)
        .join(' ')
        .toLowerCase()
        .replace(/<[^>]*>/g, ' ') // strip HTML
        .replace(/[^a-z0-9\s-]/g, ' ');

    const stop = new Set([
        'the','and','a','to','of','in','for','on','is','it','that','with','as','at','by','be','are','or','from','an','this','we','you','your','our','us','i','have','has','was','were','will','can','about','not','but','if','they','their','there','also','all','more','any','how','what','when','which','who'
    ]);
    const words = textBlob.split(/\s+/).filter(w => w && w.length > 2 && !stop.has(w));
    const freq = {};
    for (const w of words) freq[w] = (freq[w] || 0) + 1;
    const topKeywords = Object.entries(freq)
        .sort((a,b) => b[1]-a[1])
        .slice(0, 50)
        .map(([word, count]) => ({word, count}));

    // Bigram (two-word phrase) frequencies
    const bigramFreq = {};
    for (let i = 0; i < words.length - 1; i++) {
        const a = words[i], b = words[i+1];
        if (stop.has(a) || stop.has(b)) continue;
        const key = `${a} ${b}`;
        bigramFreq[key] = (bigramFreq[key] || 0) + 1;
    }
    const topBigrams = Object.entries(bigramFreq)
        .sort((a,b) => b[1]-a[1])
        .slice(0, 30)
        .map(([phrase, count]) => ({phrase, count}));

    // Asset counts
    let imageCount = 0;
    const galleryRows = db.prepare("SELECT * FROM gallery").all();
    const galleryCategories = { pergola:0, cover:0, privacywall:0, decks:0, stairs:0, railing:0, lighting:0 };
    try {
        const galleryDir = path.join(__dirname, 'public', 'img', 'gallery');
        const files = fs.readdirSync(galleryDir);
        imageCount = files.filter(f => /\.(webp|png|jpe?g|gif|svg)$/i.test(f)).length;
    } catch(err) {}
    for (const g of galleryRows) {
        for (const k of Object.keys(galleryCategories)) {
            if (g[k] === 1) galleryCategories[k]++;
        }
    }

    // Content summaries
    const pagesSummary = pageRows.map(p => ({
        page: p.page,
        header: p.header || '',
        hero: !!p.hero,
        headerChars: (p.header || '').length,
        contentChars: (p.content || '').length
    }));

    const blogsSummary = blogRowsFull
        .sort((a,b) => b.id - a.id)
        .map(b => ({
            id: b.id,
            slug: b.slug,
            header: b.header || '',
            active: b.active === 1,
            hero: !!b.hero,
            headerChars: (b.header || '').length,
            contentChars: (b.content || '').length
        }));

    const totalBlogs = blogsSummary.length;
    const activeBlogs = blogsSummary.filter(b => b.active).length;

    // Time series by day (last 30 days)
    const daySessions = {};
    const dayConversions = {};
    const startRange = monthStart;
    for (const s of sessions) {
        if (!s.date || s.date < startRange) continue;
        const d = new Date(s.date);
        const key = `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}-${String(d.getUTCDate()).padStart(2,'0')}`;
        daySessions[key] = (daySessions[key] || 0) + 1;
        if (s.converted === 1) dayConversions[key] = (dayConversions[key] || 0) + 1;
    }
    const timeSeries = Object.keys(daySessions)
        .sort()
        .map(k => ({ day: k, sessions: daySessions[k], conversions: dayConversions[k] || 0 }));

    const firstDate = new Date(monthStart);
    const lastDate = new Date(now);

    return {
        totals: {
            totalSessions,
            convertedSessions,
            conversionRate: totalSessions ? (convertedSessions / totalSessions) : 0,
            imageCount,
            avgPagesPerSession: totalSessions ? (totalPagesAll / totalSessions) : 0,
            bounceRate: totalSessions ? (bouncesAll / totalSessions) : 0
        },
        ranges: {
            last7, last30, last90,
            conv7, conv30, conv90
        },
        pages: topPages,
        entries: topEntryPages,
        exits: topExitPages,
        funnel: {
            sessionsWithContact,
            sessionsWithRequest,
            sessionsWithCareer
        },
        keywords: topKeywords,
        bigrams: topBigrams,
        gallery: {
            categories: galleryCategories
        },
        content: {
            pages: pagesSummary,
            blogs: blogsSummary,
            totalBlogs,
            activeBlogs
        },
        timeSeries,
        month: {
            totals: {
                totalSessions: Object.values(daySessions).reduce((a,b)=>a+b,0),
                convertedSessions: Object.values(dayConversions).reduce((a,b)=>a+b,0),
                conversionRate: (Object.values(daySessions).reduce((a,b)=>a+b,0)) ? (Object.values(dayConversions).reduce((a,b)=>a+b,0) / Object.values(daySessions).reduce((a,b)=>a+b,0)) : 0,
                avgPagesPerSession: (Object.values(daySessions).reduce((a,b)=>a+b,0)) ? (totalPagesMonth / Object.values(daySessions).reduce((a,b)=>a+b,0)) : 0,
                bounceRate: (Object.values(daySessions).reduce((a,b)=>a+b,0)) ? (bouncesMonth / Object.values(daySessions).reduce((a,b)=>a+b,0)) : 0
            },
            pages: topPagesMonth,
            entries: topEntryPagesMonth,
            exits: topExitPagesMonth,
            funnel: {
                sessionsWithContact: sessionsWithContactMonth,
                sessionsWithRequest: sessionsWithRequestMonth,
                sessionsWithCareer: sessionsWithCareerMonth
            },
            timeSeries
        },
        window: {
            start: firstDate ? firstDate.toISOString() : null,
            end: lastDate ? lastDate.toISOString() : null
        }
    };
}

// Report login page
app.get('/report-login', (req,res) => {
    return res.render('report-login');
});

// Handle report password
app.post('/report-login', (req,res) => {
    const pw = (req.body && req.body.password) ? req.body.password : '';
    if (pw === 'adminreport') {
        res.cookie('reportAuth', '1', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 1000 * 60 * 60 * 4
        });
        return res.redirect('/report');
    }
    return res.render('report-login', { error: 'Invalid password' });
});

// View report HTML
app.get('/report', mustHaveReportAuth, (req,res) => {
    const metrics = buildReportMetrics();
    return res.render('report', { metrics });
});

// Download PDF
app.get('/report.pdf', mustHaveReportAuth, async (req,res) => {
    try {
        const metrics = buildReportMetrics();
        // Render EJS to HTML string
        res.render('report', { metrics }, async (err, html) => {
            if (err) {
                console.error('Render error:', err);
                return res.status(500).send('Failed to render report');
            }

            async function launchChromium() {
                const baseArgs = ['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage'];
                const common = { headless: 'new', args: baseArgs };
                // Respect env override if provided
                if (process.env.PUPPETEER_EXECUTABLE_PATH) {
                    try {
                        return await puppeteer.launch({ ...common, executablePath: process.env.PUPPETEER_EXECUTABLE_PATH });
                    } catch(e) {
                        console.error('Puppeteer launch failed with env executable:', e.message);
                    }
                }
                // Try common system paths first
                const candidates = ['/usr/bin/chromium','/usr/bin/chromium-browser','/snap/bin/chromium','/usr/bin/google-chrome','/usr/bin/google-chrome-stable'];
                for (const path of candidates) {
                    try {
                        return await puppeteer.launch({ ...common, executablePath: path });
                    } catch(e) {
                        // continue
                    }
                }
                // Fallback to default embedded Chromium
                try {
                    return await puppeteer.launch(common);
                } catch(e) {
                    console.error('Puppeteer default launch failed:', e.message);
                }
                throw new Error('Chromium launch failed; missing system libraries or browser. See https://pptr.dev/troubleshooting');
            }

            let browser;
            try {
                browser = await launchChromium();
            } catch (launchErr) {
                console.error('Puppeteer launch error:', launchErr);
                return res.status(500).send('PDF generation is temporarily unavailable on this server. Please install Chromium dependencies (libatk, pango, gtk, gbm, etc.) or set PUPPETEER_EXECUTABLE_PATH to a working browser.');
            }

            const page = await browser.newPage();
            await page.setContent(html, { waitUntil: 'networkidle0' });
            const pdf = await page.pdf({
                format: 'A4',
                printBackground: true,
                margin: { top: '20mm', right: '15mm', bottom: '20mm', left: '15mm' }
            });
            await browser.close();

            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', 'attachment; filename="dynamicdecks-report.pdf"');
            return res.send(pdf);
        });
    } catch(err) {
        console.error('PDF error:', err);
        return res.status(500).send('Failed to generate PDF');
    }
});

// Simple health check for Puppeteer environment
app.get('/puppeteer-health', async (req, res) => {
    try {
        const baseArgs = ['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage'];
        const common = { headless: 'new', args: baseArgs };
        let usedPath = 'bundled';
        let browser;

        // Try env path first
        if (process.env.PUPPETEER_EXECUTABLE_PATH) {
            try {
                usedPath = process.env.PUPPETEER_EXECUTABLE_PATH;
                browser = await puppeteer.launch({ ...common, executablePath: usedPath });
            } catch (e) {
                // reset and continue
                usedPath = 'bundled';
            }
        }
        // Try system candidates
        if (!browser) {
            const candidates = ['/usr/bin/chromium','/usr/bin/chromium-browser','/snap/bin/chromium','/usr/bin/google-chrome','/usr/bin/google-chrome-stable'];
            for (const path of candidates) {
                try {
                    usedPath = path;
                    browser = await puppeteer.launch({ ...common, executablePath: path });
                    break;
                } catch(e) {
                    // keep trying
                }
            }
        }
        // Try bundled
        if (!browser) {
            try {
                usedPath = 'bundled';
                browser = await puppeteer.launch(common);
            } catch(e) {
                return res.status(500).json({ ok: false, error: e.message, hint: 'Install system Chromium or set PUPPETEER_EXECUTABLE_PATH' });
            }
        }

        const version = await browser.version();
        await browser.close();
        return res.json({ ok: true, usedPath, version, envPath: process.env.PUPPETEER_EXECUTABLE_PATH || null });
    } catch (err) {
        console.error('Puppeteer health error:', err);
        return res.status(500).json({ ok: false, error: err.message });
    }
});


app.get("/blog/:slug", (req,res) => {


    const blogStatement = db.prepare("SELECT * FROM blogs WHERE slug = ?")
    const pageData = blogStatement.get(req.params.slug)

    if (!pageData) return res.status(404).render("404")

    let html = pageData.content || '';
    const trimmed = html.trim();
    if (trimmed && !trimmed.startsWith('<')) {
        html = marked.parse(html);
    }
    pageData.content = enhanceContentHtml(html);

    return res.render("page", {pageData})
})

app.get("/activate/:id", (req,res) => {

    const activateStatement = db.prepare("UPDATE blogs set active = 1 WHERE id = ?")
    activateStatement.run(req.params.id)

    return res.redirect("/blog")
})


app.get("/blog", (req,res) => {

    const blogStatement = db.prepare("SELECT * FROM blogs ORDER BY id DESC");
    const blogs = blogStatement.all()

    return res.render("blog", {blogs})
})

app.get("/delete-blog/:id", mustBeLoggedIn, (req,res) => {
    const blogStatement = db.prepare("DELETE FROM blogs WHERE id = ?")
    blogStatement.run(req.params.id);

    return res.redirect("/console")
})


function mustBeLoggedIn(req, res, next){
    if(req.user) {
        return next()
    }
    else
    {
        return res.redirect("/request")
    }
}

app.get("/", (req, res) => {

    //Grab content from the database page -> "home"
    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?");
    const pageData = contentStatement.get("home");

    pageData.content = enhanceContentHtml(marked.parse(pageData.content)); // Convert Markdown to HTML

    const fallbackHero = "/img/ui/wood-light.webp";
    const heroRows = db.prepare(
        "SELECT page, hero FROM pages WHERE page IN ('decks', 'pergolas', 'covers', 'construction')"
    ).all();
    const serviceHeroes = {
        decks: fallbackHero,
        pergolas: fallbackHero,
        covers: fallbackHero,
        construction: fallbackHero,
    };
    for (const row of heroRows) {
        if (row && row.page && row.hero) serviceHeroes[row.page] = row.hero;
    }

    return res.render("homepage", { pageData, serviceHeroes });
})

app.get("/logout", (req,res) => {
    res.clearCookie("login")
    res.redirect("/")
})

app.get("/decks", (req, res) => {


    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?");
    const pageData = contentStatement.get("decks");

    pageData.content = enhanceContentHtml(marked.parse(pageData.content)); // Convert Markdown to HTML

    return res.render("page", {pageData});

})

app.get("/pergolas", (req, res) => {

    //Grab content from the database page -> "home"
    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?");
    const pageData = contentStatement.get("pergolas");

    pageData.content = enhanceContentHtml(marked.parse(pageData.content)); // Convert Markdown to HTML

    return res.render("page", {pageData});
})

app.get("/privacy-policy", (req, res) => {

    return res.render("privacy");
})

app.post("/update-title/:id", mustBeLoggedIn, (req,res) => {
    const title = req.body

    console.log(title)

    const updatePage = db.prepare("UPDATE pages set header = ? WHERE page = ?")
    updatePage.run(title.title,req.params.id)

    res.json({success: true})
})

app.post('/upload-image', mustBeLoggedIn, upload.single('image'), async (req, res) => {
  try {
    const originalPath = req.file.path; // e.g., uploads/original.jpg
    const filename = path.parse(req.file.filename).name; // without extension
    const newFilename = filename + '.webp';
    const newPath = path.join(path.dirname(originalPath), newFilename);

    // Resize and convert to WebP
    await sharp(originalPath)
      .resize({ width: 640, height: 640, fit: 'inside' }) // Maintain aspect ratio
      .webp({ quality: 80 }) // Adjust quality as needed
      .toFile(newPath);

    // Optionally delete the original file
    fs.unlinkSync(originalPath);

    console.log('Image uploaded and resized:', newFilename);
    res.json({ success: true, filename: newFilename });
  } catch (error) {
    console.error('Error processing image:', error);
    res.status(500).json({ success: false, error: 'Image processing failed' });
  }
});
  
app.post('/upload-video/:id', mustBeLoggedIn, upload.single('video'), (req, res) => {
    console.log('Video uploaded:', req.file.filename);
    res.json({ success: true });
  });


const markdownUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, './public/img'); // Temp folder before conversion
    },
    filename: (req, file, cb) => {
      const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname);
      cb(null, uniqueName);
    }
  }),
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Unsupported file type'), false);
  }
});

app.post("/upload-markdown-image", mustBeLoggedIn, markdownUpload.single("image"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded or invalid file type." });
  }

  const outputDir = path.join('public', 'img', 'markdown');
  const filename = `${Date.now()}-${Math.round(Math.random() * 1e9)}.webp`;
  const outputPath = path.join(outputDir, filename);

  try {
    // Ensure output directory exists
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

    // Convert to .webp
    await sharp(req.file.path)
      .webp({ quality: 85 })
      .toFile(outputPath);

    // Delete temp uploaded file
    fs.unlink(req.file.path, (err) => {
      if (err) console.error("Error deleting temp file:", err);
    });

    // Send markdown-compatible image URL
    const publicUrl = `/img/markdown/${filename}`;
    return res.json({ url: publicUrl });
  } catch (err) {
    console.error("Image upload failed:", err);
    return res.status(500).json({ error: "Failed to process image." });
  }
});


app.post('/edit/:id', mustBeLoggedIn, upload.single('heroImage'), fileSizeLimiter, async (req, res) => {
    const id = req.params.id;
    const { header, content } = req.body;
    const file = req.file;

    const isNumeric = /^\d+$/.test(id);
    const table = isNumeric ? 'blogs' : 'pages';
    let heroUrl = null;

    try {
        // Get current hero image path if any
        const currentRow = isNumeric
            ? db.prepare("SELECT hero FROM blogs WHERE id = ?").get(Number(id))
            : db.prepare("SELECT hero FROM pages WHERE page = ?").get(id);

        const oldHeroPath = currentRow?.hero ? path.join('public', currentRow.hero) : null;

        if (file && file.path) {
            // Convert to .webp
            const webpFilename = `${Date.now()}-${Math.round(Math.random() * 1e9)}.webp`;
            const webpPath = path.join('public/img/gallery', webpFilename);
            const publicWebPath = `/img/gallery/${webpFilename}`;

            await sharp(file.path)
                .webp({ quality: 85 })
                .toFile(webpPath);

            heroUrl = publicWebPath;

            // Delete uploaded original
            fs.unlink(file.path, (err) => {
                if (err) console.error('Error deleting uploaded original image:', err);
            });

            // Delete old hero if exists
            if (oldHeroPath && fs.existsSync(oldHeroPath)) {
                fs.unlink(oldHeroPath, (err) => {
                    if (err) console.error("Error deleting old hero:", err);
                });
            }
        }

        // Prepare and run update
        const stmt = heroUrl
            ? db.prepare(`UPDATE ${table} SET header = ?, content = ?, hero = ? WHERE ${isNumeric ? 'id' : 'page'} = ?`)
            : db.prepare(`UPDATE ${table} SET header = ?, content = ? WHERE ${isNumeric ? 'id' : 'page'} = ?`);

        const params = heroUrl
            ? [header, content, heroUrl, isNumeric ? Number(id) : id]
            : [header, content, isNumeric ? Number(id) : id];

        stmt.run(...params);

        res.redirect('/console');
    } catch (err) {
        console.error("Update error:", err);
        res.status(500).send("Something went wrong updating the content.");
    }
});



app.get("/covers", (req, res) => {

    //Grab content from the database page -> "home"
    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?");
    const pageData = contentStatement.get("covers");

    pageData.content = enhanceContentHtml(marked.parse(pageData.content)); // Convert Markdown to HTML

    return res.render("page", {pageData});
})

app.get("/construction", (req, res) => {

    //Grab content from the database page -> "home"
    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?");
    const pageData = contentStatement.get("construction");

    pageData.content = enhanceContentHtml(marked.parse(pageData.content)); // Convert Markdown to HTML

    return res.render("page", {pageData});
})

app.get("/home-show", (req, res) => {

    return res.render("home-show")
})

app.get("/contact", (req, res) => {

    return res.render("contact")
})

app.post("/contact", async (req, res) => {
  try {
    const formData = req.body;

    // 1. Verify Google reCAPTCHA token first
    // The token will be in formData['g-recaptcha-response'] or similar, 
    // confirm what your front end sends (Google sends 'g-recaptcha-response')

    const captchaToken = formData["g-recaptcha-response"];
    if (!captchaToken) {
      return res.status(400).send("No captcha token provided");
    }

    // Verify with Google
    const secretKey = process.env.GOOGLEKEY;
    const verifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaToken}`;

    const captchaResponse = await fetch(verifyURL, { method: "POST" });
    const captchaResult = await captchaResponse.json();

    if (!captchaResult.success) {
      return res.status(400).send("Captcha verification failed");
    }

    // 2. Forward the form data to Formspree

    // Formspree expects form data in URL-encoded or JSON
    // We'll send as URL-encoded:

    const urlSearchParams = new URLSearchParams();

    // Append all keys except captcha token
    for (const key in formData) {
      if (key !== "g-recaptcha-response") {
        urlSearchParams.append(key, formData[key]);
      }
    }

    const formspreeRes = await fetch("https://formspree.io/f/mzblyrwl", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
      },
      body: urlSearchParams.toString(),
    });

    if (!formspreeRes.ok) {
      return res.status(500).send("Error submitting form to Formspree");
    }

        const formspreeJson = await formspreeRes.json();

        // 3. Respond to your client
        const acceptsJson = req.xhr || (req.headers.accept && req.headers.accept.includes("application/json"));
        if (acceptsJson) {
            return res.status(200).json({ message: "Form submitted successfully", formspree: formspreeJson });
        }
        return res.redirect("/thanks");

  } catch (err) {
    console.error(err);
        if (req.xhr || (req.headers.accept && req.headers.accept.includes("application/json"))) {
            return res.status(500).json({ error: "Internal server error" });
        }
        return res.status(500).send("Internal server error");
  }
});

app.get("/gallery", (req, res) => {

    const query = req.query.filter || null;

    let imagesStatement = null;
    let images = null;

    if(query == null)
    {
        imagesStatement = db.prepare("SELECT * FROM gallery")
        images = imagesStatement.all()
    }
    else
    {
        imagesStatement = db.prepare(`SELECT * FROM gallery WHERE ${query} = 1`)
        images = imagesStatement.all()
    }

    

    return res.render("gallery", {images, query})
})

app.get("/request", (req,res) => {
    return res.render("request")
})

app.get("/login/:id", (req,res) => {
    let emailTo = "chris@chrispricemusic.net";

    if(req.params.id == "dynamic")
        emailTo = "decksinbox@gmail.com"

    const salt = bcrypt.genSaltSync(10)

    const emailsecret = bcrypt.hashSync(req.params.id + Date.now().toString(), salt).replace(/[^a-zA-Z0-9]/g, '')
    const emailSuperSecret = bcrypt.hashSync(emailsecret, salt);

    const updateStatement = db.prepare("UPDATE login set key = ? where username = ?")
    updateStatement.run(emailSuperSecret, req.params.id)

    html =`
    <html>
        <head>
            <title>Check it out!</title>
            <link rel="icon" type="image/x-icon" href="https://www.dropbox.com/scl/fi/cvyp68qqihaakktohzyt8/favicon.ico?dl=1">
            <link href="https://fonts.googleapis.com/css2?family=Open+Sans:ital,wght@0,300..800;1,300..800&family=Oswald:wght@200..700&display=swap" rel="stylesheet">
            <link rel="stylesheet" href="https://use.typekit.net/ayz5zyc.css">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                html, body, div, span, applet, object, iframe, h1, h2, h3, h4, h5, h6, p, blockquote, pre, a, abbr, acronym, address, big, cite, code, del, dfn, em, font, img, ins, kbd, q, s, samp, small, strike, strong, sub, sup, tt, var, b, u, i, center, dl, dt, dd, ol, ul, li, fieldset, form, label, legend, caption {
                    margin: 0;
                    padding: 0;
                    border: 0;
                    outline: 0;
                    vertical-align: baseline;
                    background: transparent;
                    font-family: "Open Sans", sans-serif;
                    font-weight: 400;
                    font-style: normal;
                    line-height: 1.4em;
                    word-wrap: break-word;
                }
                
                :root{

                --background-dark:rgb(0, 0, 0);
                --background-light:rgb(0, 0, 0);
                --color-light: #0d0b0e;
                --color-dark: #211825;
                --color-primary: #b026ff;
                --color-primary-active: #5d00b1;
                --color-secondary: #00d2b8;
                --color-secondary-active: #009784;
                --border-width: 1.5px;
                --color-reverse: #333;
                }

                body{
                    color: var(--color-light);
                }

                i {
                    font-style: italic;
                }


                h1, h2, h3, h4, h5{
                    margin: 12px;
                    font-family: "quicksand", sans-serif;
                    font-weight: 700;
                    font-style: normal;
                }

                a{
                    color: var(--color-light);
                    font-weight: 600;
                }

                a:hover{
                    color: var(--color-primary)
                }
                .card{
                    margin-top: 10px;
                    padding: 12px;
                    background-color: var(--color-primary);
                    box-shadow: 2px 2px 0px var(--color-dark);

                }

                .card a:hover{
                    color: var(--color-primary-active);
                }

                .card small{
                    color: var(--color-light);
                }

                hr{
                    width: 80%;
                    border-color: var(--color-primary)
                }

                .grid{
                    display: grid;
                    grid-template-columns: 1fr 1fr 1fr;
                }

                @media only screen and (width<=1000px){
                    .grid{
                        grid-template-columns: 1fr;
                        margin-left: 8px;
                        margin-right: 8px;
                    }
                }

                p{
                    margin: 12px;
                }

            </style>
        </head>
        <header style="text-align: center;">
            <br>
            <img src="https://raw.githubusercontent.com/chrisprice5614/Form-Test/refs/heads/main/logoBlack.png" alt="Chris price music logo">
            
        </header>
        <body>
            <br>
            <h2>Sign into Dynamic Decks Website Admin</h2>
            <p>Hello, you've sent a request to sign into the admin console for Dynamic Decks. If this was not you, please ignore this email.</p>
            <p>Click <a href="https://dynamicdecksinc.com/login?user=${req.params.id}&key=${emailsecret}">here</a> to sign in</p>
            
        </body>
        <br>
        <hr>
        <footer style="text-align: center;">
            <br>
            <a href="chrispricemusic.net">chrispricemusic.net</a>
            <br>
        </footer>
    </html>
    `

    sendEmail(emailTo,"Sign In Request for Dynamic Decks, Inc",html)

    res.render("check")
})

app.get("/console", mustBeLoggedIn, (req,res) => {

    const sessionStatement = db.prepare("SELECT * FROM sessions ORDER BY date")
    const sessions = sessionStatement.all()

    const blogStatement = db.prepare("SELECT * FROM blogs")
    const blogs = blogStatement.all();

    return res.render("console", {sessions, blogs})
})

app.get("/career", (req, res) => {
    return res.render("career")
})

app.get("/add-blog", mustBeLoggedIn, (req,res) => {
    return res.render("add-blog")
})

app.post("/career", (req,res) => {
    const firstname = req.body.firstname || "undefined";
    const lastname = req.body.lastname || "undefined";
    const phone = req.body.phone || "undefined";
    const address = req.body.address || "undefined";
    const email = req.body.email || "undefined";
    const education = req.body.education || "undefined";
    const message = req.body.message || "undefined";


    html =`
    <html>
        <head>
            <title>Check it out!</title>
            <link rel="icon" type="image/x-icon" href="https://www.dropbox.com/scl/fi/cvyp68qqihaakktohzyt8/favicon.ico?dl=1">
            <link href="https://fonts.googleapis.com/css2?family=Open+Sans:ital,wght@0,300..800;1,300..800&family=Oswald:wght@200..700&display=swap" rel="stylesheet">
            <link rel="stylesheet" href="https://use.typekit.net/ayz5zyc.css">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                html, body, div, span, applet, object, iframe, h1, h2, h3, h4, h5, h6, p, blockquote, pre, a, abbr, acronym, address, big, cite, code, del, dfn, em, font, img, ins, kbd, q, s, samp, small, strike, strong, sub, sup, tt, var, b, u, i, center, dl, dt, dd, ol, ul, li, fieldset, form, label, legend, caption {
                    margin: 0;
                    padding: 0;
                    border: 0;
                    outline: 0;
                    vertical-align: baseline;
                    background: transparent;
                    font-family: "Open Sans", sans-serif;
                    font-weight: 400;
                    font-style: normal;
                    line-height: 1.4em;
                    word-wrap: break-word;
                }
                
                :root{

                --background-dark:rgb(0, 0, 0);
                --background-light:rgb(0, 0, 0);
                --color-light: #0d0b0e;
                --color-dark: #211825;
                --color-primary: #b026ff;
                --color-primary-active: #5d00b1;
                --color-secondary: #00d2b8;
                --color-secondary-active: #009784;
                --border-width: 1.5px;
                --color-reverse: #333;
                }

                body{
                    color: var(--color-light);
                }

                i {
                    font-style: italic;
                }


                h1, h2, h3, h4, h5{
                    margin: 12px;
                    font-family: "quicksand", sans-serif;
                    font-weight: 700;
                    font-style: normal;
                }

                a{
                    color: var(--color-light);
                    font-weight: 600;
                }

                a:hover{
                    color: var(--color-primary)
                }
                .card{
                    margin-top: 10px;
                    padding: 12px;
                    background-color: var(--color-primary);
                    box-shadow: 2px 2px 0px var(--color-dark);

                }

                .card a:hover{
                    color: var(--color-primary-active);
                }

                .card small{
                    color: var(--color-light);
                }

                hr{
                    width: 80%;
                    border-color: var(--color-primary)
                }

                .grid{
                    display: grid;
                    grid-template-columns: 1fr 1fr 1fr;
                }

                @media only screen and (width<=1000px){
                    .grid{
                        grid-template-columns: 1fr;
                        margin-left: 8px;
                        margin-right: 8px;
                    }
                }

                p{
                    margin: 12px;
                }

            </style>
        </head>
        <header style="text-align: center;">
            <br>
            <img src="https://raw.githubusercontent.com/chrisprice5614/Form-Test/refs/heads/main/logoBlack.png" alt="Chris price music logo">
            
        </header>
        <body>
            <br>
            <br>
            <h1>You've Reived an Application</h1>
            <br>
            <br>
            <b>Name: </b>${firstname} ${lastname}
            <br>
            <br>
            <b>Phone Number: </b><a href="tel:${phone}">${phone}</a>
            <br>
            <br>
            <b>Address: </b>${address}
            <br>
            <br>
            <b>Email: </b><a href="mailto:${email}">${email}</a>
            <br>
            <br>
            <b>Highest Education: </b>${education}
            <br>
            <br>
            <b>Previous Work Experience: </b>${message}
            <b>
        </body>
        <br>
        <hr>
        <footer style="text-align: center;">
            
            <a href="chrispricemusic.net">chrispricemusic.net</a>
            <br>
        </footer>
    </html>
    `

    sendEmail("decksinbox@gmail.com","Job Application",html)

    return res.render("application")


})

app.get("/delete/:id", mustBeLoggedIn, (req, res) => {

    const getImageStatement = db.prepare("SELECT * FROM gallery WHERE id = ?")
    const imageInQuestion = getImageStatement.get(req.params.id);

    const imagePath = imageInQuestion.path;

    fs.unlink(__dirname+"/public/img/gallery/"+imagePath, (err) => {
        if (err) {
          console.error('Error deleting the file:', err);
        }

      });

    const deleteStatement = db.prepare("DELETE FROM gallery WHERE id = ?");
    deleteStatement.run(req.params.id);

    return res.redirect("/gallery");
})

app.post('/upload', upload.single('file'), fileSizeLimiter, async (req, res) => {
  try {
    const description = req.body.description;
    const pergola = req.body.pergola ? 1 : 0;
    const cover = req.body.cover ? 1 : 0;
    const privacywall = req.body.privacywall ? 1 : 0;
    const decks = req.body.decks ? 1 : 0;
    const stairs = req.body.stairs ? 1 : 0;
    const railing = req.body.railing ? 1 : 0;
    const lighting = req.body.lighting ? 1 : 0;

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded or unsupported file type.' });
    }

    const originalPath = req.file.path;
    const filenameWithoutExt = path.parse(req.file.filename).name;
    const newFilename = filenameWithoutExt + '.webp';
    const newPath = path.join(path.dirname(originalPath), newFilename);

    // Resize and convert to WebP
    await sharp(originalPath)
      .resize({ width: 1080, height: 1080, fit: 'inside' }) // maintain aspect ratio
      .webp({ quality: 90 })
      .toFile(newPath);

    // Delete the original upload to save space
    fs.unlink(originalPath, (err) => {
        if (err) {
          console.error('Error deleting the file:', err);
        }

      });;

    console.log('Uploaded and processed file:', newFilename);

    // Save the new WebP file name in DB
    const uploadStatement = db.prepare(`
      INSERT INTO gallery (path, description, pergola, cover, privacywall, decks, stairs, railing, lighting)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    uploadStatement.run(newFilename, description, pergola, cover, privacywall, decks, stairs, railing, lighting);

    res.redirect("/gallery");
  } catch (err) {
    console.error('Image processing failed:', err);
    res.status(500).send('Image processing failed.');
  }
});

app.get("/img/ui/", mustBeLoggedIn, (req,res) => {
    const uiDir = path.join(__dirname, "public", "img", "ui");

  fs.readdir(uiDir, (err, files) => {
    if (err) {
      console.error("Error reading /img/ui:", err);
      return res.status(500).json({ error: "Unable to read image directory." });
    }

    // Optionally filter to include only image files
    const imageFiles = files.filter(file =>
      /\.(jpe?g|png|gif|webp|svg)$/i.test(file)
    );

    res.json(imageFiles);
  });
})

app.get("/allimg", mustBeLoggedIn, (req, res) => {
    const folderName = "gallery";
    const uiDir = path.join(__dirname, "public", "img", folderName);
  
    fs.readdir(uiDir, (err, files) => {
      if (err) {
        console.error("Error reading /img/" + folderName + ":", err);
        return res.status(500).json({ error: "Unable to read image directory." });
      }
  
      // Optionally filter to include only image files
      const imageFiles = files.filter(file =>
        /\.(jpe?g|png|gif|webp|svg)$/i.test(file)
      );
  
      // Return full relative paths like '/img/gallery/filename.jpg'
      const imagePaths = imageFiles.map(file => `/img/${folderName}/${file}`);
  
      console.log(imagePaths)
      res.json(imagePaths);
    });
});

app.post('/add-blog', mustBeLoggedIn, upload.single('heroImage'), async (req, res) => {
    const { header, content } = req.body;
    const file = req.file;

    if (!header || !content) {
        return res.status(400).send("Header and content are required.");
    }

    const slug = slugify(header, { lower: true, strict: true });
    const page = header;
    const active = 1;
    let hero = null;

    try {
        if (file && file.path) {
            const webpFilename = `${Date.now()}-${Math.round(Math.random() * 1e9)}.webp`;
            const webpPath = path.join('public/img/gallery', webpFilename);
            const publicWebPath = `/img/gallery/${webpFilename}`;

            await sharp(file.path)
                .webp({ quality: 85 })
                .toFile(webpPath);

            hero = publicWebPath;

            // Delete original upload (JPG/PNG)
            fs.unlink(file.path, (err) => {
                if (err) console.error('Error deleting original image:', err);
            });
        }

        db.prepare(`
            INSERT INTO blogs (page, active, slug, hero, content, header)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(page, active, slug, hero, content, header);

        res.redirect(`/blog/${slug}`);
    } catch (err) {
        console.error("Add blog error:", err);
        res.status(500).send("Something went wrong adding the blog.");
    }
});

app.get("/about.html", (req,res) => {
    res.redirect("/decks");
})

app.get("/blog.html", (req,res) => {
    res.redirect("/blog");
})

app.get("/construction.html", (req,res) => {
    res.redirect("/construction");
})

app.get("/contact.html", (req,res) => {
    res.redirect("/contact");
})

app.get("/decks.html", (req,res) => {
    res.redirect("/decks");
})

app.get("/home.html", (req,res) => {
    res.redirect("/");
})

app.get("/covers.html", (req,res) => {
    res.redirect("/covers");
})

app.get("/gallery.html", (req,res) => {
    res.redirect("/gallery");
})

app.get("/index.html", (req,res) => {
    res.redirect("/");
})

app.get("/pergolas.html", (req,res) => {
    res.redirect("/pergolas");
})

app.get("/thanks.html", (req,res) => {
    res.redirect("/thanks");
})

app.get("/edit/:id", mustBeLoggedIn, (req,res) => {

    const id = req.params.id;
    let pageData;

    if (/^\d+$/.test(req.params.id)) {
        const contentStatement = db.prepare("SELECT * FROM blogs WHERE id = ?")
        pageData = contentStatement.get(req.params.id)
    } else {
        const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?")
        pageData = contentStatement.get(req.params.id)
    }

    return res.render("edit-page", {id, pageData})
})

app.get("/login", (req,res) => {
    const user = req.query.user
    const key = req.query.key

    try {
        const getKeyStatement = db.prepare("SELECT * FROM login WHERE username = ?")
        const compareKey = getKeyStatement.get(user).key

        const compare = bcrypt.compareSync(key, compareKey)

        if(compare)
        {
            const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + (60*60*4), key: key}, JWT_SECRET) //Creating a token for logging in

            res.cookie("login",ourTokenValue, {
                httpOnly: true,
                secure: true,
                sameSite: "lax",
                maxAge: 1000 * 60 * 60 * 4
            }) //name, string to remember,
        }
    } catch(err) {
        return res.redirect("/")
    }

    return res.redirect("/console")
})

app.use((req, res, next) => {
    res.status(404).render('404'); // render the 404.ejs page
});



//What port we're listening on
app.listen(3005)