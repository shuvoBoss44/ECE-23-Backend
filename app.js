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

// Load environment variables
dotenv.config();

// Validate environment variables
const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET', 'FRONTEND_URL'];
const missingVars = requiredEnvVars.filter((varName) => !process.env[varName]);
if (missingVars.length > 0) {
    console.error('Missing required environment variables:', missingVars.join(', '));
    process.exit(1);
}

// Initialize Express
const app = express();

// CORS configuration
const corsOptions = {
    origin: (origin, callback) => {
        const allowedOrigins = process.env.NODE_ENV === 'production'
            ? ['https://ece-23.vercel.app', 'https://yourapp.onrender.com']
            : ['http://localhost:5173'];
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // Increased to 200 for better UX
    message: { message: 'Too many requests from this IP, please try again later.' },
});

// Middleware
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
        },
    },
}));
app.use(limiter);
app.use(express.json({ limit: '10kb' })); // Limit JSON payload size
app.use(cookieParser());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    connectTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    retryWrites: true,
    writeConcern: { w: 'majority' },
}).then(() => console.log('MongoDB connected'))
    .catch((err) => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    roll: { type: String, required: true, unique: true, trim: true },
    college: { type: String, required: true, trim: true },
    school: { type: String, required: true, trim: true },
    district: { type: String, required: true, trim: true },
    quote: { type: String, required: true, trim: true },
    socialMedia: {
        facebook: { type: String, default: '', trim: true },
        phone: { type: String, default: '', trim: true },
        instagram: { type: String, default: '', trim: true },
        whatsapp: { type: String, default: '', trim: true },
    },
    image: { type: String, required: true, trim: true },
    password: { type: String, required: true },
    canAnnounce: { type: Boolean, default: false },
}, { timestamps: true });

userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    try {
        this.password = await bcrypt.hash(this.password, 10);
        next();
    } catch (err) {
        next(err);
    }
});

userSchema.methods.comparePassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

// Note Schema
const noteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true, trim: true },
    semester: { type: String, required: true, trim: true },
    courseNo: { type: String, required: true, trim: true },
    pdf: { type: String, required: true, trim: true },
}, { timestamps: true });

const Note = mongoose.model('Note', noteSchema);

// Announcement Schema
const announcementSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    content: { type: String, required: true, trim: true },
    creator: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

const Announcement = mongoose.model('Announcement', announcementSchema);

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
    let token = req.cookies.token; // Prioritize cookie
    if (!token && req.header('Authorization')) {
        token = req.header('Authorization').replace('Bearer ', '');
    }
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id).select('-password');
        if (!req.user) {
            return res.status(401).json({ message: 'User not found' });
        }
        next();
    } catch (err) {
        console.error('Token verification failed:', err.message);
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Validate Google Drive URL
const isValidGoogleDriveUrl = (url) => {
    return /^https:\/\/(drive\.google\.com\/file\/d\/|docs\.google\.com\/.*id=)[a-zA-Z0-9_-]+/.test(url);
};

// User Routes
app.get("/", (req, res) => {
    res.json({ message: "API is running" });
});

app.post(
    '/api/users/login',
    [
        body('roll').notEmpty().trim().withMessage('Roll is required'),
        body('password').notEmpty().withMessage('Password is required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { roll, password } = req.body;
        try {
            const user = await User.findOne({ roll });
            if (!user) {
                return res.status(400).json({ message: 'Invalid credentials' });
            }
            const isMatch = await user.comparePassword(password);
            if (!isMatch) {
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
            user.password = newPassword; // Will be hashed by pre-save hook
            await user.save();
            res.json({ message: 'Password updated successfully' });
        } catch (err) {
            console.error('Password update error:', err);
            res.status(500).json({ message: 'Server error' });
        }
    }
);

app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (err) {
        console.error('Users fetch error:', err.message);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/users/me', authMiddleware, async (req, res) => {
    try {
        res.json(req.user);
    } catch (err) {
        console.error('User fetch error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get(
    '/api/users/:roll',
    [param('roll').notEmpty().trim().withMessage('Roll is required')],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { roll } = req.params;
        try {
            const user = await User.findOne({ roll }).select('-password');
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
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
    res.json({ message: 'Logout successful' });
});

// Note Routes
app.post(
    '/api/notes',
    authMiddleware,
    [
        body('title').notEmpty().trim().withMessage('Title is required'),
        body('semester').notEmpty().trim().withMessage('Semester is required'),
        body('courseNo').notEmpty().trim().withMessage('Course number is required'),
        body('pdf').notEmpty().trim().withMessage('Google Drive URL is required')
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
            res.status(400).json({ message: 'Server error' });
        }
    }
);

app.put(
    '/api/notes/:id',
    authMiddleware,
    [
        param('id').isMongoId().withMessage('Invalid note ID'),
        body('title').optional().notEmpty().trim().withMessage('Title cannot be empty'),
        body('semester').optional().notEmpty().trim().withMessage('Semester cannot be empty'),
        body('courseNo').optional().notEmpty().trim().withMessage('Course number cannot be empty'),
        body('pdf').optional().trim().custom((value) => isValidGoogleDriveUrl(value)).withMessage('Invalid Google Drive URL'),
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
            note.pdf = pdf || note.pdf;
            note.updatedAt = Date.now();
            await note.save();
            res.json(note);
        } catch (err) {
            console.error('Note update error:', err);
            res.status(400).json({ message: 'Server error' });
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
        res.status(500).json({ message: 'Server error' });
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
            res.status(500).json({ message: 'Server error' });
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
            res.status(500).json({ message: 'Server error' });
        }
    }
);

// Announcement Routes
app.post(
    '/api/announcements',
    authMiddleware,
    [
        body('title').notEmpty().trim().withMessage('Title is required'),
        body('content').notEmpty().trim().withMessage('Content is required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const user = await User.findById(req.user._id);
            if (!user.canAnnounce) {
                return res.status(403).json({ message: 'Not authorized to create announcements' });
            }
            const { title, content } = req.body;
            const announcement = new Announcement({
                title,
                content,
                creator: req.user._id,
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
        body('title').optional().notEmpty().trim().withMessage('Title cannot be empty'),
        body('content').optional().notEmpty().trim().withMessage('Content cannot be empty'),
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
            if (announcement.creator.toString() !== req.user._id.toString()) {
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
            if (announcement.creator.toString() !== req.user._id.toString()) {
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
    if (err.name === 'ValidationError') {
        return res.status(400).json({ message: 'Validation error', errors: err.errors });
    }
    if (err.name === 'MongoError' && err.code === 11000) {
        return res.status(400).json({ message: 'Duplicate key error', field: Object.keys(err.keyValue) });
    }
    res.status(500).json({ message: 'Internal server error' });
});

// Bind to Render's port and host
const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running on port ${port}`);
});

module.exports = app;