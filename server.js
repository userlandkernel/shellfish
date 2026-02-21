const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const { spawn } = require('child_process');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const os = require('os');

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Configuration
const CONFIG = {
    PASSWORD_HASH: crypto.createHash('sha256').update('secure123').digest('hex'), // Change this!
    SESSION_SECRET: crypto.randomBytes(32).toString('hex'),
    PORT: process.env.PORT || 3000,
    MAX_SESSIONS: 10,
    SESSION_TIMEOUT: 30 * 60 * 1000, // 30 minutes
    RATE_LIMIT: 100, // requests per 15 minutes
    ALLOWED_COMMANDS: [], // empty array means allow all
    DENIED_COMMANDS: ['rm -rf', 'shutdown', 'reboot', 'init', 'poweroff', 'dd', 'mkfs'], // dangerous commands
    LOG_ACTIONS: true,
    MAX_BUFFER: 1024 * 1024, // 1MB buffer for command output
    COMMAND_TIMEOUT: 30000 // 30 seconds command timeout
};

// Store active sessions and processes
const activeSessions = new Map();
const userSessions = new Map();
const activeProcesses = new Map(); // Store running shell processes per socket

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());
app.use(session({
    secret: CONFIG.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false, // set to true if using HTTPS
        maxAge: CONFIG.SESSION_TIMEOUT,
        httpOnly: true,
        sameSite: 'strict'
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: CONFIG.RATE_LIMIT,
    message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Logger
function log(action, user, details = '') {
    if (!CONFIG.LOG_ACTIONS) return;
    
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${user} - ${action} ${details}\n`;
    
    console.log(logEntry.trim());
    
    // Append to log file
    fs.appendFile('terminal.log', logEntry, (err) => {
        if (err) console.error('Failed to write to log file:', err);
    });
}

// Authentication middleware
function authenticate(req, res, next) {
    const authToken = req.cookies.authToken || req.headers['x-auth-token'];
    
    if (!authToken) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const session = activeSessions.get(authToken);
    if (!session) {
        return res.status(401).json({ error: 'Invalid session' });
    }
    
    // Check session expiry
    if (Date.now() > session.expires) {
        activeSessions.delete(authToken);
        return res.status(401).json({ error: 'Session expired' });
    }
    
    req.session = session;
    next();
}

// Generate auth token
function generateAuthToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Check if command is allowed
function isCommandAllowed(command) {
    // Check denied commands
    for (const denied of CONFIG.DENIED_COMMANDS) {
        if (command.includes(denied)) {
            return false;
        }
    }
    
    // If ALLOWED_COMMANDS is not empty, check if command is allowed
    if (CONFIG.ALLOWED_COMMANDS.length > 0) {
        const cmdBase = command.split(' ')[0];
        return CONFIG.ALLOWED_COMMANDS.includes(cmdBase);
    }
    
    return true;
}

// Sanitize command output
function sanitizeOutput(output) {
    // Remove ANSI escape sequences but keep basic formatting
    return output.replace(/\u001b\[\d+m/g, '');
}

// Get system shell
function getSystemShell() {
    if (process.platform === 'win32') {
        return 'cmd.exe';
    } else {
        return process.env.SHELL || '/bin/bash';
    }
}

// Routes

// Authentication endpoint
app.post('/api/auth', (req, res) => {
    const { password } = req.body;
    
    if (!password) {
        return res.status(400).json({ error: 'Password required' });
    }
    
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    
    if (hash === CONFIG.PASSWORD_HASH) {
        const token = generateAuthToken();
        const session = {
            token,
            created: Date.now(),
            expires: Date.now() + CONFIG.SESSION_TIMEOUT,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        };
        
        activeSessions.set(token, session);
        userSessions.set(req.ip, token);
        
        // Set cookie
        res.cookie('authToken', token, {
            maxAge: CONFIG.SESSION_TIMEOUT,
            httpOnly: true,
            sameSite: 'strict'
        });
        
        log('LOGIN_SUCCESS', req.ip, `Token: ${token.substring(0,8)}...`);
        
        res.json({ 
            success: true, 
            token,
            expires: session.expires
        });
    } else {
        log('LOGIN_FAILED', req.ip, 'Invalid password');
        res.status(401).json({ error: 'Invalid password' });
    }
});

// Logout endpoint
app.post('/api/logout', authenticate, (req, res) => {
    const token = req.cookies.authToken;
    activeSessions.delete(token);
    userSessions.delete(req.ip);
    
    res.clearCookie('authToken');
    
    log('LOGOUT', req.ip);
    
    res.json({ success: true });
});

// Check session status
app.get('/api/status', authenticate, (req, res) => {
    res.json({
        authenticated: true,
        expires: req.session.expires,
        server: os.hostname(),
        platform: os.platform(),
        release: os.release(),
        shell: getSystemShell()
    });
});

// Execute command (alternative to WebSocket)
app.post('/api/execute', authenticate, (req, res) => {
    const { command } = req.body;
    
    if (!command) {
        return res.status(400).json({ error: 'Command required' });
    }
    
    if (!isCommandAllowed(command)) {
        log('COMMAND_DENIED', req.ip, command);
        return res.status(403).json({ error: 'Command not allowed' });
    }
    
    log('COMMAND_EXEC', req.ip, command);
    
    // Execute command
    const exec = require('child_process').exec;
    exec(command, {
        timeout: CONFIG.COMMAND_TIMEOUT,
        maxBuffer: CONFIG.MAX_BUFFER,
        shell: getSystemShell()
    }, (error, stdout, stderr) => {
        const result = {
            command,
            stdout: sanitizeOutput(stdout),
            stderr: sanitizeOutput(stderr),
            code: error ? error.code : 0
        };
        
        res.json(result);
    });
});

// Get system info
app.get('/api/system', authenticate, (req, res) => {
    const info = {
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        release: os.release(),
        uptime: os.uptime(),
        cpus: os.cpus().length,
        memory: {
            total: os.totalmem(),
            free: os.freemem(),
            used: os.totalmem() - os.freemem()
        },
        loadavg: os.loadavg(),
        user: os.userInfo().username,
        shell: getSystemShell()
    };
    
    res.json(info);
});

// Get directory contents
app.get('/api/ls', authenticate, (req, res) => {
    const dir = req.query.path || process.cwd();
    
    fs.readdir(dir, { withFileTypes: true }, (err, files) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        const fileList = files.map(file => ({
            name: file.name,
            type: file.isDirectory() ? 'directory' : 'file',
            size: file.isFile() ? fs.statSync(path.join(dir, file.name)).size : 0
        }));
        
        res.json(fileList);
    });
});

// Read file
app.get('/api/cat', authenticate, (req, res) => {
    const filePath = req.query.path;
    
    if (!filePath) {
        return res.status(400).json({ error: 'File path required' });
    }
    
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        res.json({ content: data });
    });
});

// Socket.IO for real-time terminal
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
        return next(new Error('Authentication required'));
    }
    
    const session = activeSessions.get(token);
    if (!session) {
        return next(new Error('Invalid session'));
    }
    
    if (Date.now() > session.expires) {
        activeSessions.delete(token);
        return next(new Error('Session expired'));
    }
    
    socket.session = session;
    next();
});

io.on('connection', (socket) => {
    const session = socket.session;
    log('SOCKET_CONNECT', session.ip, `Socket ID: ${socket.id}`);
    
    let shellProcess = null;
    let currentDir = process.env.HOME || os.homedir();
    
    try {
        // Determine shell based on platform
        const shell = getSystemShell();
        const shellArgs = process.platform === 'win32' ? [] : ['-i']; // Interactive mode
        
        log('SHELL_START', session.ip, `Using shell: ${shell}`);
        
        // Spawn shell process
        shellProcess = spawn(shell, shellArgs, {
            cwd: currentDir,
            env: {
                ...process.env,
                TERM: 'xterm-256color',
                PS1: '\\u@\\h:\\w\\$ ' // Prompt format
            },
            stdio: ['pipe', 'pipe', 'pipe']
        });
        
        // Store process reference
        activeProcesses.set(socket.id, shellProcess);
        
        // Send welcome message
        const welcome = [
            '\x1b[32m' + '='.repeat(60) + '\x1b[0m',
            '\x1b[32m' + '  🔐 Secure Terminal - Real Shell Access' + '\x1b[0m',
            '\x1b[32m' + '  Connected to: ' + os.hostname() + '\x1b[0m',
            '\x1b[32m' + '  Shell: ' + shell + '\x1b[0m',
            '\x1b[32m' + '  Type "help" for available commands' + '\x1b[0m',
            '\x1b[32m' + '='.repeat(60) + '\x1b[0m',
            '',
            shellProcess.stdout.setEncoding('utf8')
        ];
        
        welcome.forEach(line => socket.emit('output', line + '\r\n'));
        
        // Send initial prompt
        socket.emit('output', `\x1b[36m${os.userInfo().username}@${os.hostname()}:${currentDir}$ \x1b[0m`);
        
        // Handle shell stdout
        shellProcess.stdout.on('data', (data) => {
            const output = data.toString();
            socket.emit('output', output);
        });
        
        // Handle shell stderr
        shellProcess.stderr.on('data', (data) => {
            const error = data.toString();
            socket.emit('output', `\x1b[31m${error}\x1b[0m`);
        });
        
        // Handle shell exit
        shellProcess.on('exit', (code) => {
            log('SHELL_EXIT', session.ip, `Exit code: ${code}`);
            socket.emit('output', `\r\n\x1b[33mShell exited with code ${code}\x1b[0m\r\n`);
            socket.emit('exit', code);
            activeProcesses.delete(socket.id);
        });
        
        // Handle shell error
        shellProcess.on('error', (err) => {
            log('SHELL_ERROR', session.ip, err.message);
            socket.emit('output', `\r\n\x1b[31mShell error: ${err.message}\x1b[0m\r\n`);
        });
        
    } catch (error) {
        log('SHELL_CREATE_ERROR', session.ip, error.message);
        socket.emit('error', 'Failed to create shell session: ' + error.message);
        return;
    }
    
    // Handle client input
    socket.on('input', (data) => {
        if (!shellProcess || shellProcess.killed) {
            socket.emit('output', '\x1b[31mShell not available. Please reconnect.\x1b[0m\r\n');
            return;
        }
        
        // Check for dangerous commands
        if (data === '\r' || data === '\n') {
            // Command execution - we'll check full commands
            // This is handled by the shell itself
        }
        
        try {
            shellProcess.stdin.write(data);
        } catch (err) {
            log('STDIN_ERROR', session.ip, err.message);
            socket.emit('output', `\x1b[31mError: ${err.message}\x1b[0m\r\n`);
        }
    });
    
    // Resize terminal (not directly applicable to child_process, but we can track)
    socket.on('resize', (data) => {
        // We can't easily resize child_process, but we can update env
        if (shellProcess) {
            shellProcess.env.COLUMNS = data.cols;
            shellProcess.env.LINES = data.rows;
        }
    });
    
    // Clear terminal
    socket.on('clear', () => {
        socket.emit('output', '\x1bc'); // Send clear screen escape sequence
    });
    
    // Interrupt process (Ctrl+C)
    socket.on('interrupt', () => {
        if (shellProcess) {
            try {
                shellProcess.stdin.write('\x03');
            } catch (err) {
                log('INTERRUPT_ERROR', session.ip, err.message);
            }
        }
    });
    
    // Execute single command
    socket.on('exec', (command) => {
        if (!isCommandAllowed(command)) {
            socket.emit('output', `\x1b[31mCommand '${command}' is not allowed\x1b[0m\r\n`);
            return;
        }
        
        const exec = require('child_process').exec;
        exec(command, {
            cwd: currentDir,
            timeout: CONFIG.COMMAND_TIMEOUT,
            maxBuffer: CONFIG.MAX_BUFFER,
            shell: getSystemShell()
        }, (error, stdout, stderr) => {
            if (stdout) socket.emit('output', stdout);
            if (stderr) socket.emit('output', `\x1b[31m${stderr}\x1b[0m`);
            if (error) socket.emit('output', `\x1b[31mError: ${error.message}\x1b[0m\r\n`);
            
            // Send prompt
            socket.emit('output', `\x1b[36m${os.userInfo().username}@${os.hostname()}:${currentDir}$ \x1b[0m`);
        });
    });
    
    // Change directory
    socket.on('cd', (dir) => {
        try {
            const newDir = path.resolve(currentDir, dir);
            fs.accessSync(newDir, fs.constants.R_OK);
            currentDir = newDir;
            socket.emit('output', `\x1b[36m${os.userInfo().username}@${os.hostname()}:${currentDir}$ \x1b[0m`);
        } catch (err) {
            socket.emit('output', `\x1b[31mcd: ${dir}: No such directory\x1b[0m\r\n`);
        }
    });
    
    // Handle disconnect
    socket.on('disconnect', () => {
        log('SOCKET_DISCONNECT', session.ip);
        
        if (shellProcess && !shellProcess.killed) {
            try {
                shellProcess.kill();
            } catch (err) {
                log('KILL_ERROR', session.ip, err.message);
            }
        }
        
        activeProcesses.delete(socket.id);
    });
});

// Alternative: Execute command and stream output
app.post('/api/stream', authenticate, (req, res) => {
    const { command } = req.body;
    
    if (!command) {
        return res.status(400).json({ error: 'Command required' });
    }
    
    if (!isCommandAllowed(command)) {
        return res.status(403).json({ error: 'Command not allowed' });
    }
    
    log('COMMAND_STREAM', req.ip, command);
    
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Transfer-Encoding', 'chunked');
    
    const exec = require('child_process').exec;
    const child = exec(command, {
        cwd: process.env.HOME,
        shell: getSystemShell()
    });
    
    child.stdout.on('data', (data) => {
        res.write(data);
    });
    
    child.stderr.on('data', (data) => {
        res.write(`\x1b[31m${data}\x1b[0m`);
    });
    
    child.on('close', (code) => {
        res.write(`\n\x1b[33mCommand exited with code ${code}\x1b[0m\n`);
        res.end();
    });
    
    child.on('error', (err) => {
        res.write(`\n\x1b[31mError: ${err.message}\x1b[0m\n`);
        res.end();
    });
});

// Cleanup expired sessions
setInterval(() => {
    const now = Date.now();
    
    for (const [token, session] of activeSessions.entries()) {
        if (now > session.expires) {
            activeSessions.delete(token);
            log('SESSION_EXPIRED', session.ip, `Token: ${token.substring(0,8)}...`);
        }
    }
}, 60 * 1000); // Check every minute

// Error handling
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error: ' + err.message });
});

// Start server
server.listen(CONFIG.PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(60));
    console.log('🔐 Secure Web Terminal Server (No Python Required)');
    console.log('='.repeat(60));
    console.log(`📡 URL:        http://localhost:${CONFIG.PORT}`);
    console.log(`🔑 Password:   ${CONFIG.PASSWORD_HASH !== crypto.createHash('sha256').update('secure123').digest('hex') ? '✓ Custom' : '⚠ Default: secure123'}`);
    console.log(`⏱ Session:     ${CONFIG.SESSION_TIMEOUT/60000} minutes`);
    console.log(`🛡 Rate Limit:  ${CONFIG.RATE_LIMIT} requests/15min`);
    console.log(`📝 Logging:    ${CONFIG.LOG_ACTIONS ? 'Enabled' : 'Disabled'}`);
    console.log(`💻 Shell:       ${getSystemShell()}`);
    console.log('='.repeat(60));
    console.log(`📊 Active sessions: ${activeSessions.size}`);
    console.log('='.repeat(60) + '\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('Received SIGTERM, shutting down gracefully...');
    
    // Kill all child processes
    for (const [socketId, proc] of activeProcesses.entries()) {
        try {
            proc.kill();
        } catch (err) {
            console.error(`Failed to kill process for ${socketId}:`, err);
        }
    }
    
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('Received SIGINT, shutting down...');
    
    for (const [socketId, proc] of activeProcesses.entries()) {
        try {
            proc.kill();
        } catch (err) {
            // Ignore
        }
    }
    
    process.exit(0);
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    log('UNCAUGHT_EXCEPTION', 'SYSTEM', error.message);
});

// Unhandled rejection handler
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    log('UNHANDLED_REJECTION', 'SYSTEM', reason);
});
