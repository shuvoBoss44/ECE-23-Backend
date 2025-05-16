const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const morgan = require('morgan');
const NodeCache = require('node-cache'); // New dependency for caching

// Load environment variables
dotenv.config();

// Verify environment variables
console.log('MONGO_URI:', process.env.MONGO_URI ? 'Set' : 'Missing');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? 'Set' : 'Missing');
console.log('FRONTEND_URL:', process.env.FRONTEND_URL ? 'Set' : 'Missing');
console.log('NODE_ENV:', process.env.NODE_ENV || 'development');

// Initialize Express
const app = express();

// CORS configuration
const corsOptions = {
    origin: process.env.NODE_ENV === 'production'
        ? ['https://ece-23.vercel.app', 'https://yourapp.onrender.com']
        : ['http://localhost:5173'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));

// Initialize cache
const cache = new NodeCache({ stdTTL: 900, checkperiod: 120 }); // Cache for 15 min

// Rate limiting
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per IP
    standardHeaders: true, // Add Ratelimit-* and Retry-After headers
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again later.',
    handler: (req, res, next, options) => {
        console.log(`Rate limit hit for IP: ${req.ip}, Path: ${req.path}`);
        res.status(options.statusCode).json({ message: options.message });
    },
});

const userMeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 500, // More lenient: 500 requests per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests to /api/users/me, please try again later.',
    handler: (req, res, next, options) => {
        console.log(`Rate limit hit for /api/users/me, IP: ${req.ip}`);
        res.status(options.statusCode).json({ message: options.message });
    },
});

// Middleware
app.use(morgan('combined')); // More detailed logs for debugging
app.use(helmet());
app.use(generalLimiter); // Apply general limiter to all routes
app.use(express.json());
app.use(cookieParser());

// MongoDB Connection (unchanged)
mongoose.connect(process.env.MONGO_URI, {
    connectTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    retryWrites: true,
    w: 'majority',
})
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// User Schema (unchanged)
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    roll: { type: String, required: true, unique: true },
    college: { type: String, required: true },
    school: { type: String, required: true },
    district: { type: String, required: true },
    quote: { type: String, required: true },
    socialMedia: {
        facebook: { type: String, default: '' },
        phone: { type: String, default: '' },
        instagram: { type: String, default: '' },
        whatsapp: { type: String, default: '' },
    },
    image: { type: String, required: true },
    password: { type: String, required: true },
    canAnnounce: { type: Boolean, default: false },
}, { timestamps: true });

userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

userSchema.methods.comparePassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

// Note Schema (unchanged)
const noteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    semester: { type: String, required: true },
    courseNo: { type: String, required: true },
    pdf: { type: String, required: true },
}, { timestamps: true });

const Note = mongoose.model('Note', noteSchema);

// Announcement Schema (unchanged)
const announcementSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    content: { type: String, required: true, trim: true },
    creator: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

const Announcement = mongoose.model('Announcement', announcementSchema);

// Authentication Middleware (unchanged)
const authMiddleware = async (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '') || req.cookies.token;
    console.log('AuthMiddleware - Token:', token);
    if (!token) {
        console.log('AuthMiddleware: No token provided');
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id).select('-password');
        if (!req.user) {
            console.log('AuthMiddleware: User not found for ID:', decoded.id);
            return res.status(401).json({ message: 'User not found' });
        }
        console.log('AuthMiddleware: User authenticated:', req.user.roll);
        next();
    } catch (err) {
        console.log('AuthMiddleware: Token verification failed:', err.message);
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Validate Google Drive URL (unchanged)
const isValidGoogleDriveUrl = (url) => {
    return /^https:\/\/(drive\.google\.com\/file\/d\/|docs\.google\.com\/.*id=)[a-zA-Z0-9_-]+/.test(url);
};

// User Routes (only /api/users/me and /ping modified, others unchanged)
app.get("/", (req, res) => {
    res.json("hello world");
});

// Keep-alive endpoint to prevent spin-down
app.get('/ping', (req, res) => {
    console.log(`Ping received from IP: ${req.ip}`);
    res.status(200).json({ status: 'alive' });
});

app.post(
    '/api/users/login',
    [
        body('roll').notEmpty().withMessage('Roll is required'),
        body('password').notEmpty().withMessage('Password is required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { roll, password } = req.body;
        console.log('Login attempt for roll:', roll);
        try {
            const user = await User.findOne({ roll });
            if (!user) {
                console.log('Login failed: User not found for roll:', roll);
                return res.status(400).json({ message: 'Invalid credentials' });
            }
            const isMatch = await user.comparePassword(password);
            if (!isMatch) {
                console.log('Login failed: Incorrect password for roll:', roll);
                return res.status(400).json({ message: 'Invalid credentials' });
            }
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15d' });
            const cookieOptions = {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
                maxAge: 15 * 24 * 60 * 60 * 1000, // 15 days
                path: '/',
            };
            res.cookie('token', token, cookieOptions);
            console.log('Login successful for roll:', roll, 'Cookie set with token');
            res.json({
                message: 'Login successful',
                user: { ...user._doc, password: undefined },
                token,
            });
        } catch (err) {
            console.error('Login error:', err.message);
            res.status(500).json({ message: 'Server error during login' });
        }
    }
);

app.post(
    '/api/users/update-password',
    authMiddleware,
    [
        body('currentPassword').notEmpty().withMessage('Current password is required'),
        body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { currentPassword, newPassword } = req.body;
        try {
            const user = await User.findById(req.user._id);
            const isMatch = await user.comparePassword(currentPassword);
            if (!isMatch) {
                return res.status(400).json({ message: 'Current password is incorrect' });
            }
            user.password = await bcrypt.hash(newPassword, 10);
            await user.save();
            res.json({ message: 'Password updated successfully' });
        } catch (err) {
            console.error('Password update error:', err);
            res.status(500).json({ message: err.message });
        }
    }
);

app.get('/api/users', async (req, res) => {
    console.log('Fetching users...');
    try {
        const users = await User.find().select('-password');
        console.log('Users fetched:', users.length);
        res.json(users);
    } catch (err) {
        console.error('Users fetch error:', err.message, err.stack);
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/users/me', userMeLimiter, authMiddleware, async (req, res) => {
    try {
        const cacheKey = `user_${req.user._id}`;
        const cachedUser = cache.get(cacheKey);
        if (cachedUser) {
            console.log(`Cache hit for user: ${req.user.roll}`);
            return res.json(cachedUser);
        }
        console.log(`Cache miss for user: ${req.user.roll}, fetching from DB`);
        const user = await User.findById(req.user._id).select('-password');
        if (!user) {
            console.log('User fetch: No user found for ID:', req.user._id);
            return res.status(404).json({ message: 'User not found' });
        }
        cache.set(cacheKey, user, 900); // Cache for 15 min
        console.log(`User fetched and cached: ${req.user.roll}`);
        res.json(user);
    } catch (err) {
        console.error('User fetch error:', err.message, err.stack);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get(
    '/api/users/:roll',
    [param('roll').notEmpty().withMessage('Roll is required')],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('User fetch validation errors:', errors.array());
            return res.status(400).json({ errors: errors.array() });
        }
        const { roll } = req.params;
        try {
            const user = await User.findOne({ roll }).select('-password');
            if (!user) {
                console.log('User fetch: No user found for roll:', roll);
                return res.status(404).json({ message: 'User not found' });
            }
            console.log('User fetch: Found user for roll:', roll);
            res.json(user);
        } catch (err) {
            console.error('User fetch error for roll:', roll, err.message);
            res.status(500).json({ message: 'Server error' });
        }
    }
);

app.post('/api/users/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        path: '/',
    });
    console.log('Logout: Cookie cleared');
    res.json({ message: 'Logout successful' });
});

// Note Routes (unchanged)
app.post(
    '/api/notes',
    authMiddleware,
    [
        body('title').notEmpty().withMessage('Title is required'),
        body('semester').notEmpty().withMessage('Semester is required'),
        body('courseNo').notEmpty().withMessage('Course number is required'),
        body('pdf').notEmpty().withMessage('Google Drive URL is required')
            .custom((value) => isValidGoogleDriveUrl(value)).withMessage('Invalid Google Drive URL'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { title, semester, courseNo, pdf } = req.body;
        try {
            const note = new Note({
                userId: req.user._id,
                title,
                semester,
                courseNo,
                pdf,
            });
            await note.save();
            res.status(201).json(note);
        } catch (err) {
            console.error('Note creation error:', err);
            res.status(400).json({ message: err.message });
        }
    }
);

app.put(
    '/api/notes/:id',
    authMiddleware,
    [
        param('id').isMongoId().withMessage('Invalid note ID'),
        body('title').optional().notEmpty().withMessage('Title cannot be empty'),
        body('semester').optional().notEmpty().withMessage('Semester cannot be empty'),
        body('courseNo').optional().notEmpty().withMessage('Course number cannot be empty'),
        body('pdf').optional().custom((value) => isValidGoogleDriveUrl(value)).withMessage('Invalid Google Drive URL'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { title, semester, courseNo, pdf } = req.body;
        try {
            const note = await Note.findById(req.params.id);
            if (!note) {
                return res.status(404).json({ message: 'Note not found' });
            }
            if (note.userId.toString() !== req.user._id.toString()) {
                return res.status(403).json({ message: 'Not authorized to update this note' });
            }
            note.title = title || note.title;
            note.semester = semester || note.semester;
            note.courseNo = courseNo || note.courseNo;
            if (pdf) {
                note.pdf = pdf;
            }
            note.updatedAt = Date.now();
            await note.save();
            res.json(note);
        } catch (err) {
            console.error('Note update error:', err);
            res.status(400).json({ message: err.message });
        }
    }
);

app.get('/api/notes', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        const { semester, courseNo } = req.query;
        const query = {};
        if (semester) query.semester = semester;
        if (courseNo) query.courseNo = courseNo;
        console.log('Notes query:', { page, limit, skip, query });
        const notes = await Note.find(query)
            .populate('userId', 'name roll')
            .skip(skip)
            .limit(limit)
            .sort({ createdAt: -1 });
        const total = await Note.countDocuments(query);
        res.json({
            notes,
            total,
            page,
            pages: Math.ceil(total / limit),
        });
    } catch (err) {
        console.error('Notes fetch error:', err);
        res.status(500).json({ message: err.message });
    }
});

app.get(
    '/api/notes/:userId',
    [param('userId').isMongoId().withMessage('Invalid user ID')],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const skip = (page - 1) * limit;
            const notes = await Note.find({ userId: req.params.userId })
                .populate('userId', 'name roll')
                .skip(skip)
                .limit(limit)
                .sort({ createdAt: -1 });
            const total = await Note.countDocuments({ userId: req.params.userId });
            res.json({
                notes,
                total,
                page,
                pages: Math.ceil(total / limit),
            });
        } catch (err) {
            console.error('User notes fetch error:', err);
            res.status(500).json({ message: err.message });
        }
    }
);

app.delete(
    '/api/notes/:id',
    authMiddleware,
    [param('id').isMongoId().withMessage('Invalid note ID')],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const note = await Note.findById(req.params.id);
            if (!note) {
                return res.status(404).json({ message: 'Note not found' });
            }
            if (note.userId.toString() !== req.user._id.toString()) {
                return res.status(403).json({ message: 'Not authorized to delete this note' });
            }
            await Note.findByIdAndDelete(req.params.id);
            res.json({ message: 'Note deleted' });
        } catch (err) {
            console.error('Note delete error:', err);
            res.status(500).json({ message: err.message });
        }
    }
);

// Announcement Routes (unchanged)
app.post(
    '/api/announcements',
    authMiddleware,
    [
        body('title').notEmpty().withMessage('Title is required'),
        body('content').notEmpty().withMessage('Content is required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const user = await User.findById(req.user.id);
            if (!user.canAnnounce) {
                return res.status(403).json({ message: 'Not authorized to create announcements' });
            }
            const { title, content } = req.body;
            const announcement = new Announcement({
                title,
                content,
                creator: req.user.id,
            });
            await announcement.save();
            res.status(201).json(announcement);
        } catch (err) {
            console.error('Announcement creation error:', err);
            res.status(500).json({ message: 'Server error' });
        }
    }
);

app.get('/api/announcements', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        const announcements = await Announcement.find()
            .populate('creator', 'name roll')
            .skip(skip)
            .limit(limit)
            .sort({ createdAt: -1 });
        const total = await Announcement.countDocuments();
        res.json({
            announcements,
            total,
            page,
            pages: Math.ceil(total / limit),
        });
    } catch (err) {
        console.error('Announcements fetch error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put(
    '/api/announcements/:id',
    authMiddleware,
    [
        param('id').isMongoId().withMessage('Invalid announcement ID'),
        body('title').optional().notEmpty().withMessage('Title cannot be empty'),
        body('content').optional().notEmpty().withMessage('Content cannot be empty'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const announcement = await Announcement.findById(req.params.id);
            if (!announcement) {
                return res.status(404).json({ message: 'Announcement not found' });
            }
            if (announcement.creator.toString() !== req.user.id.toString()) {
                return res.status(403).json({ message: 'Not authorized to update this announcement' });
            }
            const { title, content } = req.body;
            announcement.title = title || announcement.title;
            announcement.content = content || announcement.content;
            announcement.updatedAt = Date.now();
            await announcement.save();
            res.json(announcement);
        } catch (err) {
            console.error('Announcement update error:', err);
            res.status(500).json({ message: 'Server error' });
        }
    }
);

app.delete(
    '/api/announcements/:id',
    authMiddleware,
    [param('id').isMongoId().withMessage('Invalid announcement ID')],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const announcement = await Announcement.findById(req.params.id);
            if (!announcement) {
                return res.status(404).json({ message: 'Announcement not found' });
            }
            if (announcement.creator.toString() !== req.user.id.toString()) {
                return res.status(403).json({ message: 'Not authorized to delete this announcement' });
            }
            await Announcement.findByIdAndDelete(req.params.id);
            res.json({ message: 'Announcement deleted' });
        } catch (err) {
            console.error('Announcement delete error:', err);
            res.status(500).json({ message: 'Server error' });
        }
    }
);

// Global error handler
app.use((err, req, res, next) => {
    console.error('Global error:', err.stack);
    res.status(500).json({ message: 'Internal server error', error: err.message });
});

// Bind to Render's port and host
const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running on port ${port}`);
});

module.exports = app;