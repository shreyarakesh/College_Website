const express = require('express');
const path = require('path');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const usernames = require('./model/usernames');

// Load environment variables from .env file
dotenv.config({ path: './config.env' });

const app = express();
const PORT = process.env.PORT || 3050;
const MONGOURI = process.env.MONGOURI;

// Set up EJS as the templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware to serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to parse incoming request bodies
app.use(express.urlencoded({ extended: true }));

// Connect to MongoDB
mongoose.connect(MONGOURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('Failed to connect to MongoDB', err);
    process.exit(1);
});

// Define routes
app.get('/', (req, res) => {
    res.render('home');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => { 
    const { email, password } = req.body;

    console.log(`user email : ${email}`);
    try {
        const user = await usernames.findOne({ email }).lean();
        if (!user) {
            return res.status(400).send('Invalid username or password.');
        }

        console.log(`Stored hashed password: ${user.password}`);
        console.log(`Entered password: ${password}`);
        
        const isMatch = await bcrypt.compare(password, user.password);
        console.log(`Password match result: ${isMatch}`);

        if (isMatch) {
            res.status(200).render('home', { user });
        } else {
            return res.status(400).send('Invalid username or password.');
        }
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).send('Error logging in');
    }
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', async (req, res) => {
    const { email, password, firstName, lastName } = req.body;

    try {
        // Check if user already exists
        const existingUser = await usernames.findOne({ email });

        if (existingUser) {
            return res.status(400).send('Email already exists');
        }

        // Create new user instance
        const newUser = new usernames({
            email,
            password,
            firstName,
            lastName,
        });

        // Save user to database
        await newUser.save();
        //res.status(201).send('User created successfully');
        res.status(200).render('login');
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).send('Error signing up');
    }
});

// Password reset request route
app.get('/reset', (req, res) => {
    res.render('reset');
});

app.post('/reset', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await usernames.findOne({ email }).lean();
        if (!user) {
            return res.status(404).send('No account with that email address exists.');
        }

        const token = crypto.randomBytes(20).toString('hex');
        const resetPasswordToken = crypto.createHash('sha256').update(token).digest('hex');
        const resetPasswordExpires = Date.now() + 3600000; // 1 hour from now

        await usernames.updateOne(
            { email },
            {
                resetPasswordToken,
                resetPasswordExpires,
            }
        );

        const transporter = nodemailer.createTransport({
            service: 'Gmail', // Use your email service
            secure: false,
            auth: {
                user: process.env.EMAIL,
                pass: process.env.EMAIL_PASSWORD,
            },
            tls: {
                rejectUnauthorized: false // Avoids Node.js certificate validation error
            }
        });

        const mailOptions = {
            to: email,
            from: process.env.EMAIL,
            subject: 'Password Reset',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n`
                + `Please click on the following link, or paste this into your browser to complete the process:\n\n`
                + `http://${req.headers.host}/reset/${token}\n\n`
                + `If you did not request this, please ignore this email and your password will remain unchanged.\n`,
        };

        await transporter.sendMail(mailOptions);
        res.status(200).send('An email has been sent to ' + email + ' with further instructions.');
    } catch (error) {
        console.error('Error during password reset request:', error);
        res.status(500).send('Error requesting password reset');
    }
});

// Password reset form route
app.get('/reset/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const user = await usernames.findOne({
            resetPasswordToken: crypto.createHash('sha256').update(token).digest('hex'),
            resetPasswordExpires: { $gt: Date.now() },
        }).lean();

        if (!user) {
            return res.status(400).send('Password reset token is invalid or has expired.');
        }

        res.render('reset-password', { token });
    } catch (error) {
        console.error('Error during password reset token verification:', error);
        res.status(500).send('Error verifying password reset token');
    }
});

// Password reset form submission route
app.post('/reset/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await usernames.findOneAndUpdate(
            {
                resetPasswordToken: crypto.createHash('sha256').update(token).digest('hex'),
                resetPasswordExpires: { $gt: Date.now() },
            },
            {
                password: hashedPassword,
                resetPasswordToken: undefined,
                resetPasswordExpires: undefined,
            }
        );

        if (!user) {
            return res.status(400).send('Password reset token is invalid or has expired.');
        }

        res.status(200).send('Password has been reset successfully.');
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).send('Error resetting password');
    }
});

app.get('/', (req, res) => {
    res.render('home');
});

app.get('/about', (req, res) => {
    res.render('about');
});

app.get('/courses', (req, res) => {
    res.render('course');
});

app.get('/blog', (req, res) => {
    res.render('blog');
});

app.get('/contact', (req, res) => {
    res.render('contact');
});
// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
