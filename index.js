// Install required packages: npm install express mongoose jsonwebtoken bcryptjs dotenv socket.io express-rate-limit cors
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(cors());
app.use(express.json());

// Database Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Models
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const JobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  company: { type: String, required: true },
  description: { type: String, required: true },
  applicants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
});

const User = mongoose.model('User', UserSchema);
const Job = mongoose.model('Job', JobSchema);

// Rate Limiter
const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 50, // Max 50 requests per window per IP
  message: '⏳ Too many requests. Please try again later.',
});

app.use('/api/', apiLimiter);

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid Token' });
  }
};

// Routes
// Registration
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  const existingUser = await User.findOne({ username });
  if (existingUser) return res.status(400).json({ error: 'Username already exists' });

  const hashedPassword = await bcrypt.hash(password, 12);
  const user = new User({ username, password: hashedPassword });
  await user.save();
  res.json({ message: '✅ User registered successfully!' });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
  res.json({ token, message: '✅ Login successful!' });
});

// Create Job Posting
app.post('/api/jobs', authenticateToken, async (req, res) => {
  const { title, company, description } = req.body;
  const job = new Job({ title, company, description });
  await job.save();
  io.emit('jobUpdated', job);
  res.json({ message: '✅ Job posted successfully!', job });
});

// Get All Jobs
app.get('/api/jobs', async (req, res) => {
  const jobs = await Job.find();
  res.json(jobs);
});

// Apply for a Job
app.post('/api/jobs/:id/apply', authenticateToken, async (req, res) => {
  const job = await Job.findById(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  job.applicants.push(req.user._id);
  await job.save();
  res.json({ message: '✅ Application submitted!' });
});

// WebSocket for Real-Time Updates
io.on('connection', (socket) => {
  console.log('🟢 User connected');

  socket.on('disconnect', () => {
    console.log('🔴 User disconnected');
  });
});

// Start Server
server.listen(3000, () => console.log('🚀 Server running on http://localhost:3000'));


