const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect('mongodb://localhost/kevinplayz', { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set('useCreateIndex', true);

// Define User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    premium: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// Passport Local Strategy
passport.use(new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, user) => {
        if (err) return done(err);
        if (!user) return done(null, false, { message: 'Incorrect username.' });
        
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) return done(err);
            if (result) return done(null, user);
            else return done(null, false, { message: 'Incorrect password.' });
        });
    });
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

// Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.get('/premium', (req, res) => {
    if (req.isAuthenticated()) {
        if (req.user.premium) {
            res.send('Welcome to Premium!');
        } else {
            res.redirect('/signup');
        }
    } else {
        res.redirect('/signup');
    }
});

app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/signup.html');
});

app.post('/signup', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            username: req.body.username,
            password: hashedPassword
        });

        await user.save();
        res.redirect('/');
    } catch (error) {
        res.send('Error creating user.');
    }
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/signup',
    failureFlash: true
}));

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
