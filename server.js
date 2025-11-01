const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const querystring = require('querystring');
const nodemailer = require('nodemailer');

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

// Initialize data files
const dataDir = './data';
const uploadsDir = './uploads';

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const dataFiles = {
  users: './data/users.json',
  messages: './data/messages.json',
  feedback: './data/feedback.json',
  sessions: './data/sessions.json'
};

// Initialize empty JSON files if they don't exist
Object.values(dataFiles).forEach(file => {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify([]));
  }
});

// Email configuration (for password reset)
const emailTransporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});

// Helper functions
function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    return [];
  }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function generateSessionId() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function getISTTimestamp() {
  return new Date().toLocaleString('en-IN', { 
    timeZone: 'Asia/Kolkata',
    hour12: false 
  });
}

// Authentication middleware
function authenticate(req) {
  const cookies = parseCookies(req);
  const sessionId = cookies.sessionId;
  
  if (!sessionId) return null;
  
  const sessions = readJSON(dataFiles.sessions);
  const session = sessions.find(s => s.sessionId === sessionId);
  
  if (!session || session.expires < Date.now()) {
    return null;
  }
  
  const users = readJSON(dataFiles.users);
  const user = users.find(u => u.id === session.userId);
  
  return user || null;
}

function parseCookies(req) {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return {};
  
  return cookieHeader.split(';').reduce((cookies, cookie) => {
    const [name, value] = cookie.trim().split('=');
    cookies[name] = decodeURIComponent(value);
    return cookies;
  }, {});
}

// Main server
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // Serve static files
  if (pathname.startsWith('/public/') || pathname === '/') {
    return serveStaticFile(req, res);
  }

  // API routes
  if (pathname.startsWith('/api/')) {
    return handleAPI(req, res, parsedUrl);
  }

  // Default to index.html
  serveFile(res, './public/index.html', 'text/html');
});

function serveStaticFile(req, res) {
  let filePath = req.url === '/' ? './public/index.html' : './public' + req.url;
  
  const extname = path.extname(filePath);
  const contentTypes = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'text/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.ico': 'image/x-icon'
  };

  const contentType = contentTypes[extname] || 'text/plain';

  serveFile(res, filePath, contentType);
}

function serveFile(res, filePath, contentType, statusCode = 200) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('<h1>404 - Page Not Found</h1>');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/html' });
        res.end('<h1>500 - Internal Server Error</h1>');
      }
    } else {
      res.writeHead(statusCode, { 'Content-Type': contentType });
      res.end(data);
    }
  });
}

async function handleAPI(req, res, parsedUrl) {
  const pathname = parsedUrl.pathname;
  const method = req.method;

  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
  });

  req.on('end', async () => {
    try {
      let data = {};
      if (body) {
        try {
          data = JSON.parse(body);
        } catch {
          data = querystring.parse(body);
        }
      }

      // Auth routes
      if (pathname === '/api/register' && method === 'POST') {
        await handleRegister(res, data);
      } else if (pathname === '/api/login' && method === 'POST') {
        await handleLogin(res, data);
      } else if (pathname === '/api/logout' && method === 'POST') {
        handleLogout(res, data);
      } else if (pathname === '/api/forgot-password' && method === 'POST') {
        await handleForgotPassword(res, data);
      } else if (pathname === '/api/reset-password' && method === 'POST') {
        await handleResetPassword(res, data);
      } 
      // Chat routes
      else if (pathname === '/api/users' && method === 'GET') {
        handleGetUsers(res, req);
      } else if (pathname === '/api/messages' && method === 'GET') {
        handleGetMessages(res, req, parsedUrl.query);
      } else if (pathname === '/api/send-message' && method === 'POST') {
        handleSendMessage(res, req, data);
      } else if (pathname === '/api/upload' && method === 'POST') {
        await handleFileUpload(res, req);
      }
      // Feedback routes
      else if (pathname === '/api/feedback' && method === 'POST') {
        handleSubmitFeedback(res, req, data);
      }
      // Admin routes
      else if (pathname === '/api/admin/data' && method === 'GET') {
        handleAdminData(res, req);
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'API endpoint not found' }));
      }
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  });
}

// Authentication handlers
async function handleRegister(res, data) {
  const { username, email, password } = data;
  
  if (!username || !email || !password) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'All fields are required' }));
  }

  const users = readJSON(dataFiles.users);
  
  if (users.find(u => u.email === email)) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Email already registered' }));
  }

  if (users.find(u => u.username === username)) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Username already taken' }));
  }

  const newUser = {
    id: Date.now().toString(),
    username,
    email,
    password, // In production, hash this!
    createdAt: getISTTimestamp(),
    isAdmin: email === 'admin@chat.com' // Special admin email
  };

  users.push(newUser);
  writeJSON(dataFiles.users, users);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ message: 'Registration successful' }));
}

async function handleLogin(res, data) {
  const { email, password } = data;
  
  if (!email || !password) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Email and password are required' }));
  }

  const users = readJSON(dataFiles.users);
  const user = users.find(u => u.email === email && u.password === password);
  
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Invalid credentials' }));
  }

  const sessionId = generateSessionId();
  const sessions = readJSON(dataFiles.sessions);
  
  sessions.push({
    sessionId,
    userId: user.id,
    expires: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
  });
  
  writeJSON(dataFiles.sessions, sessions);

  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Set-Cookie': `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=86400`
  });
  
  res.end(JSON.stringify({ 
    message: 'Login successful',
    user: { id: user.id, username: user.username, email: user.email, isAdmin: user.isAdmin }
  }));
}

function handleLogout(res, data) {
  const { sessionId } = data;
  
  if (sessionId) {
    const sessions = readJSON(dataFiles.sessions);
    const filteredSessions = sessions.filter(s => s.sessionId !== sessionId);
    writeJSON(dataFiles.sessions, filteredSessions);
  }

  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Set-Cookie': 'sessionId=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
  });
  
  res.end(JSON.stringify({ message: 'Logout successful' }));
}

async function handleForgotPassword(res, data) {
  const { email } = data;
  
  if (!email) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Email is required' }));
  }

  const users = readJSON(dataFiles.users);
  const user = users.find(u => u.email === email);
  
  if (!user) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Email not found' }));
  }

  const otp = generateOTP();
  user.resetOTP = otp;
  user.otpExpires = Date.now() + (10 * 60 * 1000); // 10 minutes
  
  writeJSON(dataFiles.users, users);

  try {
    await emailTransporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}. It will expire in 10 minutes.`
    });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'OTP sent to your email' }));
  } catch (error) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Failed to send OTP' }));
  }
}

async function handleResetPassword(res, data) {
  const { email, otp, newPassword } = data;
  
  if (!email || !otp || !newPassword) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'All fields are required' }));
  }

  const users = readJSON(dataFiles.users);
  const user = users.find(u => u.email === email);
  
  if (!user || user.resetOTP !== otp || user.otpExpires < Date.now()) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Invalid or expired OTP' }));
  }

  user.password = newPassword;
  delete user.resetOTP;
  delete user.otpExpires;
  
  writeJSON(dataFiles.users, users);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ message: 'Password reset successful' }));
}

// Chat handlers
function handleGetUsers(res, req) {
  const user = authenticate(req);
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Unauthorized' }));
  }

  const users = readJSON(dataFiles.users);
  const filteredUsers = users.map(u => ({
    id: u.id,
    username: u.username,
    email: u.email
  }));

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ users: filteredUsers }));
}

function handleGetMessages(res, req, query) {
  const user = authenticate(req);
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Unauthorized' }));
  }

  const { otherUserId } = query;
  const messages = readJSON(dataFiles.messages);
  
  const userMessages = messages.filter(m =>
    (m.senderId === user.id && m.receiverId === otherUserId) ||
    (m.senderId === otherUserId && m.receiverId === user.id)
  );

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ messages: userMessages }));
}

function handleSendMessage(res, req, data) {
  const user = authenticate(req);
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Unauthorized' }));
  }

  const { receiverId, message, fileUrl } = data;
  
  if (!receiverId || (!message && !fileUrl)) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Receiver ID and message or file are required' }));
  }

  const newMessage = {
    id: Date.now().toString(),
    senderId: user.id,
    senderName: user.username,
    receiverId,
    message: message || '',
    fileUrl: fileUrl || null,
    timestamp: getISTTimestamp(),
    type: fileUrl ? 'file' : 'text'
  };

  const messages = readJSON(dataFiles.messages);
  messages.push(newMessage);
  writeJSON(dataFiles.messages, messages);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ message: 'Message sent', messageData: newMessage }));
}

async function handleFileUpload(res, req) {
  const user = authenticate(req);
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Unauthorized' }));
  }

  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
  });

  req.on('end', () => {
    try {
      const data = JSON.parse(body);
      const { fileName, fileData, fileType } = data;
      
      if (!fileName || !fileData) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'File data is required' }));
      }

      const fileId = Date.now().toString();
      const fileExtension = path.extname(fileName);
      const savedFileName = `${fileId}${fileExtension}`;
      const filePath = path.join(uploadsDir, savedFileName);
      
      // Convert base64 to buffer and save
      const buffer = Buffer.from(fileData, 'base64');
      fs.writeFileSync(filePath, buffer);

      const fileUrl = `/uploads/${savedFileName}`;
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ fileUrl, fileName }));
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'File upload failed' }));
    }
  });
}

// Feedback handler
function handleSubmitFeedback(res, req, data) {
  const user = authenticate(req);
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Unauthorized' }));
  }

  const { type, message } = data;
  
  if (!type || !message) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Type and message are required' }));
  }

  const feedback = readJSON(dataFiles.feedback);
  const newFeedback = {
    id: Date.now().toString(),
    userId: user.id,
    username: user.username,
    type,
    message,
    timestamp: getISTTimestamp(),
    status: 'pending'
  };

  feedback.push(newFeedback);
  writeJSON(dataFiles.feedback, newFeedback);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ message: 'Feedback submitted successfully' }));
}

// Admin handler
function handleAdminData(res, req) {
  const user = authenticate(req);
  if (!user || !user.isAdmin) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Unauthorized' }));
  }

  const users = readJSON(dataFiles.users);
  const messages = readJSON(dataFiles.messages);
  const feedback = readJSON(dataFiles.feedback);

  const adminData = {
    users: users.map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      createdAt: u.createdAt,
      isAdmin: u.isAdmin
    })),
    messages: messages.map(m => ({
      id: m.id,
      senderId: m.senderId,
      senderName: m.senderName,
      receiverId: m.receiverId,
      message: m.message,
      fileUrl: m.fileUrl,
      timestamp: m.timestamp,
      type: m.type
    })),
    feedback: feedback.map(f => ({
      id: f.id,
      userId: f.userId,
      username: f.username,
      type: f.type,
      message: f.message,
      timestamp: f.timestamp,
      status: f.status
    }))
  };

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(adminData));
}

// Serve uploaded files
server.on('request', (req, res) => {
  if (req.url.startsWith('/uploads/')) {
    const filePath = './uploads' + req.url.substring('/uploads'.length);
    serveFile(res, filePath, 'application/octet-stream');
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
});
