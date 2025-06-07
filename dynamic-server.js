require("dotenv").config() // Makes it so we can access .env file
const jwt = require("jsonwebtoken")//npm install jsonwebtoken dotenv
const path = require('path');
const express = require("express")//npm install express
const db = require("better-sqlite3")("database.db") //npm install better-sqlite3
const body_parser = require("body-parser")
const axios = require('axios');
const requestIp = require('request-ip');
const bcrypt = require("bcrypt") //npm install bcrypt
const cookieParser = require("cookie-parser")//npm install cookie-parser
const nodemailer = require("nodemailer")
const multer = require("multer")
const sharp = require('sharp');
const fs = require("fs");
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
        title STRING,
        active BOOL
        )
        `
    ).run()

})

createTables();


//Middleware
app.use(function (req, res, next) {
    res.locals.errors = [] //Setting the errors to nothings
    const ip = req.clientIp; //Getting the client ip for session purposes

    //Session id - ip+date encrypted so no one can steal it :)
    //Visits - Array of page visits, [{page, timeStamp}]
    //Converted - Converted to form submission

    try {
        const decoded = jwt.verify(req.cookies.login, process.env.JWTSECRET)
        req.user = decoded
    } catch(err){
        req.user = false
    }

    res.locals.user = req.user;

    try {
        const decoded = jwt.verify(req.cookies.session, process.env.JWTSECRET)
        req.session = decoded
    } catch(err) {
        let salt = bcrypt.genSaltSync(10)
        let sessionId = bcrypt.hashSync(ip + Date.now().toString(), salt)
        req.session = {exp: Math.floor(Date.now() / 1000) + (60*60*0.5), sessionId, visits: [], converted: false};
        const ourTokenValue = jwt.sign(req.session, process.env.JWTSECRET)
        

        res.cookie("session",ourTokenValue, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000 * 60 * 60 * 0.5
        }) //name, string to remember,

        const sessionStatement = db.prepare("INSERT into sessions (sessionId, date) VALUES (? , ?)")
        sessionStatement.run(req.session.sessionId, Date.now())
    }


    if(req.session.visits.size > 20)
    {
        req.session.visits.push({url: req.originalUrl, time: Date.now()})
    

        const sessionStatement = db.prepare("UPDATE sessions set visits = ? WHERE sessionId = ?")
        sessionStatement.run(JSON.stringify(req.session.visits), req.session.sessionId)

        
        req.session = {exp: Math.floor(Date.now() / 1000) + (60*60*0.5), sessionId: req.session.sessionId, visits: req.session.visits, converted: req.session.converted};

        const ourTokenValue = jwt.sign(req.session, process.env.JWTSECRET)

        res.cookie("session",ourTokenValue, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000 * 60 * 60 * 0.5
    }) //name, string to remember,
    }

    //console.log(req.session)
    
    next()
})

app.get("/thanks", (req,res) => {
    const sessionStatement = db.prepare("UPDATE sessions set converted = 1 WHERE sessionId = ?")
    sessionStatement.run(req.session.sessionId)

    return res.render("thanks")
})

app.get("/blog/:id", (req,res) => {

    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?")
    const content = contentStatement.get("blog"+req.params.id)

    const blogStatement = db.prepare("SELECT * FROM blogs WHERE id = ?")
    const blog = blogStatement.get(req.params.id)

    return res.render("single-blog", {content, blog})
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

app.post("/add-blog", mustBeLoggedIn,(req,res) => {

    const blogStatement = db.prepare("INSERT into blogs (title) VALUES (?)")
    blogStatement.run(req.body.title)

    const blogGet = db.prepare("SELECT * FROM blogs WHERE title = ?")
    const blog = blogGet.get(req.body.title)

    const pageStatement = db.prepare("INSERT into pages (page, header, content) VALUES (? , ? , ?)")
    pageStatement.run("blog"+blog.id,req.body.title, "[]")

    const contentGet = db.prepare("SELECT * FROM pages WHERE page = ?")
    const content = contentGet.get("blog"+blog.id)
   

    return res.render("single-blog", {content, blog})
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
    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?")
    const content = contentStatement.get("home")

    return res.render("homepage", {content});
})

app.get("/logout", (req,res) => {
    res.clearCookie("login")
    res.redirect("/")
})

app.get("/decks", (req, res) => {

    //Grab content from the database page -> "home"
    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?")
    const content = contentStatement.get("decks")

    return res.render("homepage", {content});
})

app.get("/pergolas", (req, res) => {

    //Grab content from the database page -> "home"
    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?")
    const content = contentStatement.get("pergolas")

    return res.render("homepage", {content});
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

app.get("/covers", (req, res) => {

    //Grab content from the database page -> "home"
    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?")
    const content = contentStatement.get("covers")

    return res.render("homepage", {content});
})

app.get("/construction", (req, res) => {

    //Grab content from the database page -> "home"
    const contentStatement = db.prepare("SELECT * FROM pages WHERE page = ?")
    const content = contentStatement.get("construction")

    return res.render("homepage", {content});
})

app.get("/contact", (req, res) => {

    return res.render("contact")
})

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

    return res.render("console", {sessions})
})

app.get("/career", (req, res) => {
    return res.render("career")
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

    sendEmail("chrisprice5614@gmail.com","Job Application",html)

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

app.post("/update/:id", mustBeLoggedIn, (req,res) => {

    const updatePage = db.prepare("UPDATE pages set content = ? WHERE page = ?")
    updatePage.run(JSON.stringify(req.body),req.params.id)

    return res.json({ success: true });
})

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

app.get("/login", (req,res) => {
    const user = req.query.user
    const key = req.query.key

    try {
        const getKeyStatement = db.prepare("SELECT * FROM login WHERE username = ?")
        const compareKey = getKeyStatement.get(user).key

        const compare = bcrypt.compareSync(key, compareKey)

        if(compare)
        {
            const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + (60*60*4), key: key}, process.env.JWTSECRET) //Creating a token for logging in

            res.cookie("login",ourTokenValue, {
                httpOnly: true,
                secure: true,
                sameSite: "strict",
                maxAge: 1000 * 60 * 60 * 4
            }) //name, string to remember,
        }
    } catch(err) {
        return res.redirect("/")
    }

    return res.redirect("/")
})

app.use((req, res, next) => {
    res.status(404).render('404'); // render the 404.ejs page
});



//What port we're listening on
app.listen(3005)