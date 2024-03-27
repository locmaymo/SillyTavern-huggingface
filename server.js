#!/usr/bin/env node

// native node modules
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const util = require('util');

// cli/fs related library imports
const open = require('open');
const sanitize = require('sanitize-filename');
const writeFileAtomicSync = require('write-file-atomic').sync;
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

// express/server related library imports
const cors = require('cors');
const doubleCsrf = require('csrf-csrf').doubleCsrf;
const express = require('express');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const responseTime = require('response-time');

// net related library imports
const net = require('net');
const dns = require('dns');
const fetch = require('node-fetch').default;

// image processing related library imports
const jimp = require('jimp');

// Unrestrict console logs display limit
util.inspect.defaultOptions.maxArrayLength = null;
util.inspect.defaultOptions.maxStringLength = null;

// local library imports
const basicAuthMiddleware = require('./src/middleware/basicAuth');
const whitelistMiddleware = require('./src/middleware/whitelist');
const { jsonParser, urlencodedParser } = require('./src/express-common.js');
const contentManager = require('./src/endpoints/content-manager');
const {
    getVersion,
    getConfigValue,
    color,
    tryParse,
    clientRelativePath,
    removeFileExtension,
    getImages,
    forwardFetchResponse,
} = require('./src/util');
const { ensureThumbnailCache } = require('./src/endpoints/thumbnails');
const { loadTokenizers } = require('./src/endpoints/tokenizers');

// Work around a node v20.0.0, v20.1.0, and v20.2.0 bug. The issue was fixed in v20.3.0.
// https://github.com/nodejs/node/issues/47822#issuecomment-1564708870
// Safe to remove once support for Node v20 is dropped.
if (process.versions && process.versions.node && process.versions.node.match(/20\.[0-2]\.0/)) {
    // @ts-ignore
    if (net.setDefaultAutoSelectFamily) net.setDefaultAutoSelectFamily(false);
}

// Set default DNS resolution order to IPv4 first
dns.setDefaultResultOrder('ipv4first');

const cliArguments = yargs(hideBin(process.argv))
    .option('autorun', {
        type: 'boolean',
        default: false,
        describe: 'Automatically launch SillyTavern in the browser.',
    }).option('corsProxy', {
        type: 'boolean',
        default: false,
        describe: 'Enables CORS proxy',
    }).option('disableCsrf', {
        type: 'boolean',
        default: false,
        describe: 'Disables CSRF protection',
    }).option('ssl', {
        type: 'boolean',
        default: false,
        describe: 'Enables SSL',
    }).option('certPath', {
        type: 'string',
        default: 'certs/cert.pem',
        describe: 'Path to your certificate file.',
    }).option('keyPath', {
        type: 'string',
        default: 'certs/privkey.pem',
        describe: 'Path to your private key file.',
    }).parseSync();

// change all relative paths
console.log(`Node version: ${process.version}. Running in ${process.env.NODE_ENV} environment.`);
const serverDirectory = __dirname;
process.chdir(serverDirectory);

const app = express();
let defautlPassword = "loc";

app.use(express.json());

app.post('/login', (req, res) => {
    const { password } = req.body;

    if (defautlPassword === password) {
        res.json({ success: true });
    } else {
        res.status(400).end();
    }
});

app.post('/change-password', (req, res) => {
    const { oldPassword, newPassword } = req.body;

    if (defautlPassword === oldPassword) {
        defautlPassword = newPassword;
        res.json({ success: true });
    } else {
        res.status(400).end();
    }
});

const spaceLink = getExternalUrl(process.env.SPACE_ID);

// lấy thông tin link space
function getExternalUrl(spaceId) {
    try {
        const [username, spacename] = spaceId.split("/");
        return `https://${username}-${spacename}.hf.space`;
    } catch (e) {
        return "";
    }
}

// // sefl ping
// const smallOperation = async () => {
//     const request = await fetch(spaceLink);
//     console.log(`self ping result for ${spaceLink}`, request.status);
//     return request;
// };

// smallOperation();

// // ping every 1 hour
// setInterval(() => {
//     smallOperation();
// }, 3600000);

app.use(compression());
app.use(responseTime());

const server_port = process.env.SILLY_TAVERN_PORT || getConfigValue('port', 8000);
const port = 7860;

const autorun = (getConfigValue('autorun', false) || cliArguments.autorun) && !cliArguments.ssl;
const listen = getConfigValue('listen', false);

const { DIRECTORIES, UPLOADS_PATH, AVATAR_WIDTH, AVATAR_HEIGHT } = require('./src/constants');

// CORS Settings //
const CORS = cors({
    origin: 'null',
    methods: ['OPTIONS'],
});

app.use(CORS);

if (listen && getConfigValue('basicAuthMode', false)) app.use(basicAuthMiddleware);

app.use(whitelistMiddleware);

// backup từ người dùng
const admZip = require('adm-zip');
// Serve static files in public folder
app.use(express.static('public'));

// Upload middleware
const upload = multer({ storage: multer.memoryStorage() });

// GET backup API  
app.get('/backup', (req, res) => {
    const zip = new admZip();

    // Lấy đường dẫn tới thư mục public
    const publicDir = `${__dirname}/public`;

    // Thêm thư mục public,
    zip.addLocalFolder(publicDir);

    zip.deleteFile('index.html');
    zip.deleteFile('style.css');
    zip.deleteFile('i18n.json');
    zip.deleteFile('context');
    zip.deleteFile('robots.txt');
    zip.deleteFile('jsconfig.json');
    zip.deleteFile('settings.json');
    zip.deleteFile('script.js');

    const entries = zip.getEntries();

    // Lọc ra entry của thư mục cần xóa và các entry con
    const folderToDelete = entries.filter(entry => {
        return (
            entry.entryName.startsWith('context') ||
            entry.entryName.startsWith('css') ||
            entry.entryName.startsWith('instruct') ||
            entry.entryName.startsWith('KoboldAI Settings') ||
            entry.entryName.startsWith('lib') ||
            entry.entryName.startsWith('movingUI') ||
            entry.entryName.startsWith('NovelAI Settings') ||
            entry.entryName.startsWith('OpenAI Settings') ||
            entry.entryName.startsWith('QuickReplies') ||
            entry.entryName.startsWith('scripts') ||
            entry.entryName.startsWith('sounds') ||
            entry.entryName.startsWith('TextGen Settings') ||
            entry.entryName.startsWith('webfonts') ||
            entry.entryName.startsWith('worldinfo')
        );
    });

    // Xóa từng entry
    folderToDelete.forEach(entry => {
        zip.deleteFile(entry);
    });

    // Lấy dữ liệu đã zip
    const buffer = zip.toBuffer();

    // Phần gửi zip to client...

    // Format ngày tháng theo định dạng mong muốn  
    const now = new Date();
    const dateString = now.getDate() + '-' + (now.getMonth() + 1) + '-' + now.getFullYear();
    res.set('Content-Type', 'application/zip');
    res.set('Content-Disposition', `attachment; filename=backup-${dateString}.zip`);

    res.send(buffer);


});

// POST restore API
app.post('/restore', upload.single('backup'), (req, res) => {
    const zip = new admZip(req.file.buffer);

    // Lấy đường dẫn tới thư mục public
    const publicDir = `${__dirname}/public`;

    // Giải nén zip  
    zip.extractAllTo(publicDir, true, true);

    res.redirect('/');
});

// Serve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
// CSRF Protection //
if (!cliArguments.disableCsrf) {
    const CSRF_SECRET = crypto.randomBytes(8).toString('hex');
    const COOKIES_SECRET = crypto.randomBytes(8).toString('hex');

    const { generateToken, doubleCsrfProtection } = doubleCsrf({
        getSecret: () => CSRF_SECRET,
        cookieName: 'X-CSRF-Token',
        cookieOptions: {
            httpOnly: true,
            sameSite: 'strict',
            secure: false,
        },
        size: 64,
        getTokenFromRequest: (req) => req.headers['x-csrf-token'],
    });

    app.get('/csrf-token', (req, res) => {
        res.json({
            'token': generateToken(res, req),
        });
    });

    app.use(cookieParser(COOKIES_SECRET));
    app.use(doubleCsrfProtection);
} else {
    console.warn('\nCSRF protection is disabled. This will make your server vulnerable to CSRF attacks.\n');
    app.get('/csrf-token', (req, res) => {
        res.json({
            'token': 'disabled',
        });
    });
}

if (getConfigValue('enableCorsProxy', false) || cliArguments.corsProxy) {
    const bodyParser = require('body-parser');
    app.use(bodyParser.json({
        limit: '200mb',
    }));
    console.log('Enabling CORS proxy');

    app.use('/proxy/:url(*)', async (req, res) => {
        const url = req.params.url; // get the url from the request path

        // Disallow circular requests
        const serverUrl = req.protocol + '://' + req.get('host');
        if (url.startsWith(serverUrl)) {
            return res.status(400).send('Circular requests are not allowed');
        }

        try {
            const headers = JSON.parse(JSON.stringify(req.headers));
            delete headers['x-csrf-token'];
            delete headers['host'];
            delete headers['referer'];
            delete headers['origin'];
            delete headers['cookie'];
            delete headers['sec-fetch-mode'];
            delete headers['sec-fetch-site'];
            delete headers['sec-fetch-dest'];

            const bodyMethods = ['POST', 'PUT', 'PATCH'];

            const response = await fetch(url, {
                method: req.method,
                headers: headers,
                body: bodyMethods.includes(req.method) ? JSON.stringify(req.body) : undefined,
            });

            // Copy over relevant response params to the proxy response
            forwardFetchResponse(response, res);

        } catch (error) {
            res.status(500).send('Error occurred while trying to proxy to: ' + url + ' ' + error);
        }
    });
} else {
    app.use('/proxy/:url(*)', async (_, res) => {
        const message = 'CORS proxy is disabled. Enable it in config.yaml or use the --corsProxy flag.';
        console.log(message);
        res.status(404).send(message);
    });
}

app.use(express.static(process.cwd() + '/public', {}));

app.use('/backgrounds', (req, res) => {
    const filePath = decodeURIComponent(path.join(process.cwd(), 'public/backgrounds', req.url.replace(/%20/g, ' ')));
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(404).send('File not found');
            return;
        }
        //res.contentType('image/jpeg');
        res.send(data);
    });
});

app.use('/characters', (req, res) => {
    const filePath = decodeURIComponent(path.join(process.cwd(), DIRECTORIES.characters, req.url.replace(/%20/g, ' ')));
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(404).send('File not found');
            return;
        }
        res.send(data);
    });
});
app.use(multer({ dest: UPLOADS_PATH, limits: { fieldSize: 10 * 1024 * 1024 } }).single('avatar'));
app.get('/', function (request, response) {
    response.sendFile(process.cwd() + '/public/index.html');
});
app.get('/version', async function (_, response) {
    const data = await getVersion();
    response.send(data);
});

app.post('/getuseravatars', jsonParser, function (request, response) {
    var images = getImages('public/User Avatars');
    response.send(JSON.stringify(images));

});

app.post('/deleteuseravatar', jsonParser, function (request, response) {
    if (!request.body) return response.sendStatus(400);

    if (request.body.avatar !== sanitize(request.body.avatar)) {
        console.error('Malicious avatar name prevented');
        return response.sendStatus(403);
    }

    const fileName = path.join(DIRECTORIES.avatars, sanitize(request.body.avatar));

    if (fs.existsSync(fileName)) {
        fs.rmSync(fileName);
        return response.send({ result: 'ok' });
    }

    return response.sendStatus(404);
});

app.post('/savetheme', jsonParser, (request, response) => {
    if (!request.body || !request.body.name) {
        return response.sendStatus(400);
    }

    const filename = path.join(DIRECTORIES.themes, sanitize(request.body.name) + '.json');
    writeFileAtomicSync(filename, JSON.stringify(request.body, null, 4), 'utf8');

    return response.sendStatus(200);
});

app.post('/savemovingui', jsonParser, (request, response) => {
    if (!request.body || !request.body.name) {
        return response.sendStatus(400);
    }

    const filename = path.join(DIRECTORIES.movingUI, sanitize(request.body.name) + '.json');
    writeFileAtomicSync(filename, JSON.stringify(request.body, null, 4), 'utf8');

    return response.sendStatus(200);
});

app.post('/savequickreply', jsonParser, (request, response) => {
    if (!request.body || !request.body.name) {
        return response.sendStatus(400);
    }

    const filename = path.join(DIRECTORIES.quickreplies, sanitize(request.body.name) + '.json');
    writeFileAtomicSync(filename, JSON.stringify(request.body, null, 4), 'utf8');

    return response.sendStatus(200);
});

app.post('/deletequickreply', jsonParser, (request, response) => {
    if (!request.body || !request.body.name) {
        return response.sendStatus(400);
    }

    const filename = path.join(DIRECTORIES.quickreplies, sanitize(request.body.name) + '.json');
    if (fs.existsSync(filename)) {
        fs.unlinkSync(filename);
    }

    return response.sendStatus(200);
});


app.post('/uploaduseravatar', urlencodedParser, async (request, response) => {
    if (!request.file) return response.sendStatus(400);

    try {
        const pathToUpload = path.join(UPLOADS_PATH, request.file.filename);
        const crop = tryParse(request.query.crop);
        let rawImg = await jimp.read(pathToUpload);

        if (typeof crop == 'object' && [crop.x, crop.y, crop.width, crop.height].every(x => typeof x === 'number')) {
            rawImg = rawImg.crop(crop.x, crop.y, crop.width, crop.height);
        }

        const image = await rawImg.cover(AVATAR_WIDTH, AVATAR_HEIGHT).getBufferAsync(jimp.MIME_PNG);

        const filename = request.body.overwrite_name || `${Date.now()}.png`;
        const pathToNewFile = path.join(DIRECTORIES.avatars, filename);
        writeFileAtomicSync(pathToNewFile, image);
        fs.rmSync(pathToUpload);
        return response.send({ path: filename });
    } catch (err) {
        return response.status(400).send('Is not a valid image');
    }
});


/**
 * Ensure the directory for the provided file path exists.
 * If not, it will recursively create the directory.
 *
 * @param {string} filePath - The full path of the file for which the directory should be ensured.
 */
function ensureDirectoryExistence(filePath) {
    const dirname = path.dirname(filePath);
    if (fs.existsSync(dirname)) {
        return true;
    }
    ensureDirectoryExistence(dirname);
    fs.mkdirSync(dirname);
}

/**
 * Endpoint to handle image uploads.
 * The image should be provided in the request body in base64 format.
 * Optionally, a character name can be provided to save the image in a sub-folder.
 *
 * @route POST /uploadimage
 * @param {Object} request.body - The request payload.
 * @param {string} request.body.image - The base64 encoded image data.
 * @param {string} [request.body.ch_name] - Optional character name to determine the sub-directory.
 * @returns {Object} response - The response object containing the path where the image was saved.
 */
app.post('/uploadimage', jsonParser, async (request, response) => {
    // Check for image data
    if (!request.body || !request.body.image) {
        return response.status(400).send({ error: 'No image data provided' });
    }

    try {
        // Extracting the base64 data and the image format
        const splitParts = request.body.image.split(',');
        const format = splitParts[0].split(';')[0].split('/')[1];
        const base64Data = splitParts[1];
        const validFormat = ['png', 'jpg', 'webp', 'jpeg', 'gif'].includes(format);
        if (!validFormat) {
            return response.status(400).send({ error: 'Invalid image format' });
        }

        // Constructing filename and path
        let filename;
        if (request.body.filename) {
            filename = `${removeFileExtension(request.body.filename)}.${format}`;
        } else {
            filename = `${Date.now()}.${format}`;
        }

        // if character is defined, save to a sub folder for that character
        let pathToNewFile = path.join(DIRECTORIES.userImages, sanitize(filename));
        if (request.body.ch_name) {
            pathToNewFile = path.join(DIRECTORIES.userImages, sanitize(request.body.ch_name), sanitize(filename));
        }

        ensureDirectoryExistence(pathToNewFile);
        const imageBuffer = Buffer.from(base64Data, 'base64');
        await fs.promises.writeFile(pathToNewFile, imageBuffer);
        response.send({ path: clientRelativePath(pathToNewFile) });
    } catch (error) {
        console.log(error);
        response.status(500).send({ error: 'Failed to save the image' });
    }
});

app.post('/listimgfiles/:folder', (req, res) => {
    const directoryPath = path.join(process.cwd(), 'public/user/images/', sanitize(req.params.folder));

    if (!fs.existsSync(directoryPath)) {
        fs.mkdirSync(directoryPath, { recursive: true });
    }

    try {
        const images = getImages(directoryPath);
        return res.send(images);
    } catch (error) {
        console.error(error);
        return res.status(500).send({ error: 'Unable to retrieve files' });
    }
});


function cleanUploads() {
    try {
        if (fs.existsSync(UPLOADS_PATH)) {
            const uploads = fs.readdirSync(UPLOADS_PATH);

            if (!uploads.length) {
                return;
            }

            console.debug(`Cleaning uploads folder (${uploads.length} files)`);
            uploads.forEach(file => {
                const pathToFile = path.join(UPLOADS_PATH, file);
                fs.unlinkSync(pathToFile);
            });
        }
    } catch (err) {
        console.error(err);
    }
}

/**
 * Redirect a deprecated API endpoint URL to its replacement. Because fetch, form submissions, and $.ajax follow
 * redirects, this is transparent to client-side code.
 * @param {string} src The URL to redirect from.
 * @param {string} destination The URL to redirect to.
 */
function redirect(src, destination) {
    app.use(src, (req, res) => {
        console.warn(`API endpoint ${src} is deprecated; use ${destination} instead`);
        // HTTP 301 causes the request to become a GET. 308 preserves the request method.
        res.redirect(308, destination);
    });
}

// Redirect deprecated character API endpoints
redirect('/createcharacter', '/api/characters/create');
redirect('/renamecharacter', '/api/characters/rename');
redirect('/editcharacter', '/api/characters/edit');
redirect('/editcharacterattribute', '/api/characters/edit-attribute');
redirect('/v2/editcharacterattribute', '/api/characters/merge-attributes');
redirect('/deletecharacter', '/api/characters/delete');
redirect('/getcharacters', '/api/characters/all');
redirect('/getonecharacter', '/api/characters/get');
redirect('/getallchatsofcharacter', '/api/characters/chats');
redirect('/importcharacter', '/api/characters/import');
redirect('/dupecharacter', '/api/characters/duplicate');
redirect('/exportcharacter', '/api/characters/export');

// Redirect deprecated chat API endpoints
redirect('/savechat', '/api/chats/save');
redirect('/getchat', '/api/chats/get');
redirect('/renamechat', '/api/chats/rename');
redirect('/delchat', '/api/chats/delete');
redirect('/exportchat', '/api/chats/export');
redirect('/importgroupchat', '/api/chats/group/import');
redirect('/importchat', '/api/chats/import');
redirect('/getgroupchat', '/api/chats/group/get');
redirect('/deletegroupchat', '/api/chats/group/delete');
redirect('/savegroupchat', '/api/chats/group/save');

// Redirect deprecated group API endpoints
redirect('/getgroups', '/api/groups/all');
redirect('/creategroup', '/api/groups/create');
redirect('/editgroup', '/api/groups/edit');
redirect('/deletegroup', '/api/groups/delete');

// Redirect deprecated worldinfo API endpoints
redirect('/getworldinfo', '/api/worldinfo/get');
redirect('/deleteworldinfo', '/api/worldinfo/delete');
redirect('/importworldinfo', '/api/worldinfo/import');
redirect('/editworldinfo', '/api/worldinfo/edit');

// Redirect deprecated stats API endpoints
redirect('/getstats', '/api/stats/get');
redirect('/recreatestats', '/api/stats/recreate');
redirect('/updatestats', '/api/stats/update');

// Redirect deprecated backgrounds API endpoints
redirect('/getbackgrounds', '/api/backgrounds/all');
redirect('/delbackground', '/api/backgrounds/delete');
redirect('/renamebackground', '/api/backgrounds/rename');
redirect('/downloadbackground', '/api/backgrounds/upload'); // yes, the downloadbackground endpoint actually uploads one

// OpenAI API
app.use('/api/openai', require('./src/endpoints/openai').router);

//Google API
app.use('/api/google', require('./src/endpoints/google').router);

//Anthropic API
app.use('/api/anthropic', require('./src/endpoints/anthropic').router);

// Tokenizers
app.use('/api/tokenizers', require('./src/endpoints/tokenizers').router);

// Preset management
app.use('/api/presets', require('./src/endpoints/presets').router);

// Secrets managemenet
app.use('/api/secrets', require('./src/endpoints/secrets').router);

// Thumbnail generation. These URLs are saved in chat, so this route cannot be renamed!
app.use('/thumbnail', require('./src/endpoints/thumbnails').router);

// NovelAI generation
app.use('/api/novelai', require('./src/endpoints/novelai').router);

// Third-party extensions
app.use('/api/extensions', require('./src/endpoints/extensions').router);

// Asset management
app.use('/api/assets', require('./src/endpoints/assets').router);

// File management
app.use('/api/files', require('./src/endpoints/files').router);

// Character management
app.use('/api/characters', require('./src/endpoints/characters').router);

// Chat management
app.use('/api/chats', require('./src/endpoints/chats').router);

// Group management
app.use('/api/groups', require('./src/endpoints/groups').router);

// World info management
app.use('/api/worldinfo', require('./src/endpoints/worldinfo').router);

// Stats calculation
const statsEndpoint = require('./src/endpoints/stats');
app.use('/api/stats', statsEndpoint.router);

// Background management
app.use('/api/backgrounds', require('./src/endpoints/backgrounds').router);

// Character sprite management
app.use('/api/sprites', require('./src/endpoints/sprites').router);

// Custom content management
app.use('/api/content', require('./src/endpoints/content-manager').router);

// Settings load/store
const settingsEndpoint = require('./src/endpoints/settings');
app.use('/api/settings', settingsEndpoint.router);

// Stable Diffusion generation
app.use('/api/sd', require('./src/endpoints/stable-diffusion').router);

// LLM and SD Horde generation
app.use('/api/horde', require('./src/endpoints/horde').router);

// Vector storage DB
app.use('/api/vector', require('./src/endpoints/vectors').router);

// Chat translation
app.use('/api/translate', require('./src/endpoints/translate').router);

// Emotion classification
app.use('/api/extra/classify', require('./src/endpoints/classify').router);

// Image captioning
app.use('/api/extra/caption', require('./src/endpoints/caption').router);

// Web search extension
app.use('/api/serpapi', require('./src/endpoints/serpapi').router);

// The different text generation APIs

// Ooba/OpenAI text completions
app.use('/api/backends/text-completions', require('./src/endpoints/backends/text-completions').router);

// KoboldAI
app.use('/api/backends/kobold', require('./src/endpoints/backends/kobold').router);

// OpenAI chat completions
app.use('/api/backends/chat-completions', require('./src/endpoints/backends/chat-completions').router);

// Scale (alt method)
app.use('/api/backends/scale-alt', require('./src/endpoints/backends/scale-alt').router);

// Speech (text-to-speech and speech-to-text)
app.use('/api/speech', require('./src/endpoints/speech').router);



// listen on port
app.listen(port, () => console.info(`Listening on port ${port}`))
// const tavernUrl = new URL(
//     (cliArguments.ssl ? 'https://' : 'http://') +
//     (listen ? '0.0.0.0' : '127.0.0.1') +
//     (':' + server_port),
// );

// const autorunUrl = new URL(
//     (cliArguments.ssl ? 'https://' : 'http://') +
//     ('127.0.0.1') +
//     (':' + server_port),
// );

const setupTasks = async function () {
    const version = await getVersion();

    console.log(`SillyTavern ${version.pkgVersion}` + (version.gitBranch ? ` '${version.gitBranch}' (${version.gitRevision})` : ''));

    // TODO: do endpoint init functions depend on certain directories existing or not existing? They should be callable
    // in any order for encapsulation reasons, but right now it's unknown if that would break anything.
    await settingsEndpoint.init();
    ensurePublicDirectoriesExist();
    await ensureThumbnailCache();
    contentManager.checkForNewContent();
    cleanUploads();

    await loadTokenizers();
    await statsEndpoint.init();

    const cleanupPlugins = await loadPlugins();

    const exitProcess = async () => {
        statsEndpoint.onExit();
        if (typeof cleanupPlugins === 'function') {
            await cleanupPlugins();
        }
        process.exit();
    };

    // Set up event listeners for a graceful shutdown
    process.on('SIGINT', exitProcess);
    process.on('SIGTERM', exitProcess);
    process.on('uncaughtException', (err) => {
        console.error('Uncaught exception:', err);
        exitProcess();
    });


    console.log('Launching...');

    // if (autorun) open(autorunUrl.toString());

    // console.log(color.green('SillyTavern is listening on: ' + tavernUrl));

    // if (listen) {
    //     console.log('\n0.0.0.0 means SillyTavern is listening on all network interfaces (Wi-Fi, LAN, localhost). If you want to limit it only to internal localhost (127.0.0.1), change the setting in config.yaml to "listen: false". Check "access.log" file in the SillyTavern directory if you want to inspect incoming connections.\n');
    // }
};

// Set up the server
setupTasks().catch(err => {
    console.error(err);
    process.exit(1);
});

/**
 * Loads server plugins from a directory.
 * @returns {Promise<Function>} Function to be run on server exit
 */
async function loadPlugins() {
    try {
        const pluginDirectory = path.join(serverDirectory, 'plugins');
        const loader = require('./src/plugin-loader');
        const cleanupPlugins = await loader.loadPlugins(app, pluginDirectory);
        return cleanupPlugins;
    } catch {
        console.log('Plugin loading failed.');
        return () => {};
    }
}

if (listen && !getConfigValue('whitelistMode', true) && !getConfigValue('basicAuthMode', false)) {
    if (getConfigValue('securityOverride', false)) {
        console.warn(color.red('Security has been overridden. If it\'s not a trusted network, change the settings.'));
    }
    else {
        console.error(color.red('Your SillyTavern is currently unsecurely open to the public. Enable whitelisting or basic authentication.'));
        process.exit(1);
    }
}

// if (cliArguments.ssl) {
//     https.createServer(
//         {
//             cert: fs.readFileSync(cliArguments.certPath),
//             key: fs.readFileSync(cliArguments.keyPath),
//         }, app)
//         .listen(
//             Number(tavernUrl.port) || 443,
//             tavernUrl.hostname,
//             setupTasks,
//         );
// } else {
//     http.createServer(app).listen(
//         Number(tavernUrl.port) || 80,
//         tavernUrl.hostname,
//         setupTasks,
//     );
// }

function ensurePublicDirectoriesExist() {
    for (const dir of Object.values(DIRECTORIES)) {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    }
}
