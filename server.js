// server.js - Main signaling server
const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const cors = require('cors');
const path = require('path');
const os = require('os');

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"],
        credentials: true
    },
    transports: ['websocket', 'polling']
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Store connected users
const users = new Map(); // userId -> socketId
const userSockets = new Map(); // socketId -> userId
const userStatus = new Map(); // userId -> status (online, offline, in-call)
const callSessions = new Map(); // callId -> { participants, startTime }

// Configuration
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

// Get local IP address
function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return 'localhost';
}

const LOCAL_IP = getLocalIP();

// Logging utility
function log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = type === 'error' ? '❌' : type === 'success' ? '✅' : '📢';
    console.log(`${prefix} [${timestamp}] ${message}`);
}

// Cleanup inactive users
function cleanupInactiveUsers() {
    const now = Date.now();
    // Users are considered inactive after 30 seconds of no heartbeat
    // Implementation depends on heartbeat mechanism
}

// Broadcast user list to all connected clients
function broadcastUserList() {
    const userList = Array.from(users.keys());
    const userStatusList = Array.from(userStatus.entries()).map(([userId, status]) => ({
        userId,
        status
    }));
    
    io.emit('user-list', userList);
    io.emit('user-status-list', userStatusList);
    log(`Broadcast user list: ${userList.length} users online`);
}

// Socket.IO connection handling
io.on('connection', (socket) => {
    const clientAddress = socket.handshake.address;
    log(`New client connected from ${clientAddress} (Socket ID: ${socket.id})`);

    // Handle user registration
    socket.on('register', (userId) => {
        log(`User registering: ${userId}`);
        
        // Remove any existing registration for this user
        if (users.has(userId)) {
            const oldSocketId = users.get(userId);
            if (oldSocketId !== socket.id) {
                io.to(oldSocketId).emit('force-disconnect', 'Another client connected with same ID');
                userSockets.delete(oldSocketId);
            }
        }
        
        // Register user
        users.set(userId, socket.id);
        userSockets.set(socket.id, userId);
        userStatus.set(userId, 'online');
        
        // Store userId in socket for easy access
        socket.userId = userId;
        
        // Send confirmation
        socket.emit('registration-success', {
            userId,
            timestamp: new Date().toISOString()
        });
        
        // Broadcast updated user list
        broadcastUserList();
        
        // Notify others
        socket.broadcast.emit('participant-joined', { userId });
        
        log(`User ${userId} registered successfully`, 'success');
    });

    // Handle call initiation
    socket.on('call-user', (data) => {
        const { to, from } = data;
        log(`Call initiated from ${from} to ${to}`);
        
        const targetSocketId = users.get(to);
        if (targetSocketId) {
            // Check if target is available
            if (userStatus.get(to) === 'online') {
                userStatus.set(from, 'in-call');
                userStatus.set(to, 'in-call');
                
                io.to(targetSocketId).emit('incoming-call', {
                    from,
                    timestamp: new Date().toISOString()
                });
                
                socket.emit('call-initiated', { to });
                log(`Call initiated successfully`, 'success');
            } else {
                socket.emit('call-failed', {
                    reason: 'User is busy',
                    to
                });
                log(`Call failed: ${to} is busy`, 'error');
            }
        } else {
            socket.emit('call-failed', {
                reason: 'User not found',
                to
            });
            log(`Call failed: ${to} not found`, 'error');
        }
    });

    // Handle call acceptance
    socket.on('accept-call', (data) => {
        const { to, from } = data;
        log(`Call accepted by ${from} for call with ${to}`);
        
        const targetSocketId = users.get(to);
        if (targetSocketId) {
            // Create call session
            const callId = `${from}-${to}-${Date.now()}`;
            callSessions.set(callId, {
                participants: [from, to],
                startTime: Date.now(),
                socketIds: [socket.id, targetSocketId]
            });
            
            io.to(targetSocketId).emit('call-accepted', {
                from,
                callId,
                timestamp: new Date().toISOString()
            });
            
            log(`Call ${callId} accepted`, 'success');
        }
    });

    // Handle call rejection
    socket.on('reject-call', (data) => {
        const { to, from } = data;
        log(`Call rejected by ${from}`);
        
        const targetSocketId = users.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('call-rejected', {
                from,
                reason: 'User rejected the call'
            });
        }
        
        // Reset status
        userStatus.set(from, 'online');
        userStatus.set(to, 'online');
        
        log(`Call rejected`, 'info');
    });

    // Handle WebRTC offer
    socket.on('offer', (data) => {
        const { to, from, offer } = data;
        log(`Forwarding WebRTC offer from ${from} to ${to}`);
        
        const targetSocketId = users.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('offer', {
                from,
                offer,
                timestamp: new Date().toISOString()
            });
        }
    });

    // Handle WebRTC answer
    socket.on('answer', (data) => {
        const { to, from, answer } = data;
        log(`Forwarding WebRTC answer from ${from} to ${to}`);
        
        const targetSocketId = users.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('answer', {
                from,
                answer,
                timestamp: new Date().toISOString()
            });
        }
    });

    // Handle ICE candidates
    socket.on('ice-candidate', (data) => {
        const { to, from, candidate } = data;
        log(`Forwarding ICE candidate from ${from} to ${to}`);
        
        const targetSocketId = users.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('ice-candidate', {
                from,
                candidate,
                timestamp: new Date().toISOString()
            });
        }
    });

    // Handle call end
    socket.on('end-call', (data) => {
        const { to, from } = data;
        log(`Call ended by ${from}`);
        
        // Reset status for both participants
        userStatus.set(from, 'online');
        
        const targetSocketId = users.get(to);
        if (targetSocketId) {
            userStatus.set(to, 'online');
            io.to(targetSocketId).emit('call-ended', {
                from,
                timestamp: new Date().toISOString()
            });
        }
        
        // Find and remove call session
        for (const [callId, session] of callSessions.entries()) {
            if (session.participants.includes(from) && session.participants.includes(to)) {
                callSessions.delete(callId);
                log(`Call session ${callId} ended`, 'info');
                break;
            }
        }
        
        log(`Call ended`, 'info');
    });

    // Handle typing indicator (optional)
    socket.on('typing', (data) => {
        const { to, from, isTyping } = data;
        const targetSocketId = users.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('typing', { from, isTyping });
        }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        const userId = userSockets.get(socket.id);
        log(`Client disconnected: ${userId || socket.id}`);
        
        if (userId) {
            // Notify others
            socket.broadcast.emit('participant-left', { userId });
            
            // Clean up
            users.delete(userId);
            userSockets.delete(socket.id);
            userStatus.delete(userId);
            
            // Update user list
            broadcastUserList();
            
            log(`User ${userId} removed from active users`, 'info');
        }
    });

    // Handle heartbeat
    socket.on('heartbeat', () => {
        const userId = userSockets.get(socket.id);
        if (userId) {
            // Update last seen timestamp
            // Could be used for cleanup
        }
    });

    // Handle error
    socket.on('error', (error) => {
        log(`Socket error for ${socket.id}: ${error.message}`, 'error');
    });
});

// REST API endpoints
app.get('/api/status', (req, res) => {
    res.json({
        status: 'online',
        usersOnline: users.size,
        timestamp: new Date().toISOString(),
        serverInfo: {
            host: LOCAL_IP,
            port: PORT
        }
    });
});

app.get('/api/users', (req, res) => {
    const userList = Array.from(users.keys()).map(userId => ({
        userId,
        status: userStatus.get(userId) || 'unknown'
    }));
    res.json(userList);
});

app.get('/api/user/:userId', (req, res) => {
    const { userId } = req.params;
    const isOnline = users.has(userId);
    const status = userStatus.get(userId) || 'offline';
    
    res.json({
        userId,
        isOnline,
        status,
        timestamp: new Date().toISOString()
    });
});

app.get('/api/calls/active', (req, res) => {
    const activeCalls = Array.from(callSessions.entries()).map(([callId, session]) => ({
        callId,
        participants: session.participants,
        duration: Date.now() - session.startTime
    }));
    
    res.json({
        count: activeCalls.length,
        calls: activeCalls
    });
});

// Serve the main HTML file for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    log(`Error: ${err.message}`, 'error');
    res.status(500).json({
        error: 'Internal server error',
        message: err.message
    });
});

// Start server
server.listen(PORT, HOST, () => {
    console.log('\n' + '='.repeat(50));
    console.log('🚀 Video Call Signaling Server');
    console.log('='.repeat(50));
    console.log(`📡 Local:    http://localhost:${PORT}`);
    console.log(`📡 Network:  http://${LOCAL_IP}:${PORT}`);
    console.log(`👥 Users online: ${users.size}`);
    console.log(`📊 Status API: http://localhost:${PORT}/api/status`);
    console.log('='.repeat(50) + '\n');
});

// Periodic stats logging
setInterval(() => {
    log(`Stats - Users: ${users.size}, Active calls: ${callSessions.size}`, 'info');
}, 30000);

// Graceful shutdown
process.on('SIGTERM', () => {
    log('Received SIGTERM, shutting down gracefully...');
    server.close(() => {
        log('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    log('Received SIGINT, shutting down gracefully...');
    server.close(() => {
        log('Server closed');
        process.exit(0);
    });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    log(`Uncaught Exception: ${error.message}`, 'error');
    console.error(error.stack);
});

process.on('unhandledRejection', (reason, promise) => {
    log(`Unhandled Rejection at: ${promise}, reason: ${reason}`, 'error');
});
