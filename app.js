const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const flash = require('connect-flash');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const User = require('./models/User');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(flash());

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Global variables
app.use((req, res, next) => {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

// Passport Local Strategy
passport.use(new LocalStrategy({ usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await User.findOne({ email: email });
      if (!user) {
        return done(null, false, { message: 'Incorrect email.' });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    } catch (err) {
      return done(err);
    }
  }
));

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
},
async (token, tokenSecret, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    
    if (!user) {
      user = await User.findOne({ email: profile.emails[0].value });
      
      if (user) {
        user.googleId = profile.id;
        await user.save();
      } else {
        const hashedPassword = await bcrypt.hash(crypto.randomBytes(20).toString('hex'), 10);
        user = new User({
          googleId: profile.id,
          username: profile.displayName,
          email: profile.emails[0].value,
          password: hashedPassword,
          authMethod: 'google'
        });
        await user.save();
      }
    }
    
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

// Serialize user for the session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from the session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Set view engine
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => res.render('home'));

app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      req.flash('error_msg', 'Email already registered');
      return res.redirect('/register');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ 
      username, 
      email, 
      password: hashedPassword,
      authMethod: 'local'
    });
    await user.save();
    req.flash('success_msg', 'You are now registered and can log in');
    res.redirect('/login');
  } catch (error) {
    console.error(error);
    req.flash('error_msg', 'Registration failed');
    res.redirect('/register');
  }
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) {
      req.flash('error_msg', info.message);
      return res.redirect('/login');
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      if (user.twoFactorEnabled) {
        return res.redirect('/2fa');
      }
      return res.redirect('/dashboard');
    });
  })(req, res, next);
});

app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.render('dashboard', { user: req.user });
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) { return next(err); }
    req.session.twoFactorAuthenticated = false;
    req.flash('success_msg', 'You are logged out');
    res.redirect('/login');
  });
});

// 2FA setup route
app.get('/setup-2fa', ensureAuthenticated, async (req, res) => {
  const secret = speakeasy.generateSecret({ name: 'Your App Name' });
  req.user.twoFactorSecret = secret.base32;
  await req.user.save();

  QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
    res.render('setup-2fa', { data_url, secret: secret.base32 });
  });
});

// Enable 2FA route
app.post('/enable-2fa', ensureAuthenticated, async (req, res) => {
  const { token } = req.body;
  const verified = speakeasy.totp.verify({
    secret: req.user.twoFactorSecret,
    encoding: 'base32',
    token: token
  });

  if (verified) {
    req.user.twoFactorEnabled = true;
    await req.user.save();
    req.flash('success_msg', '2FA has been enabled');
    res.redirect('/dashboard');
  } else {
    req.flash('error_msg', 'Invalid token');
    res.redirect('/setup-2fa');
  }
});

// 2FA verification route
app.get('/2fa', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  if (!req.user.twoFactorEnabled) {
    return res.redirect('/dashboard');
  }
  res.render('2fa');
});

app.post('/2fa', (req, res) => {
  const { token } = req.body;
  const secret = req.user.twoFactorSecret;

  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token
  });

  if (verified) {
    req.session.twoFactorAuthenticated = true;
    const returnTo = req.session.returnTo || '/dashboard';
    delete req.session.returnTo;
    res.redirect(returnTo);
  } else {
    req.flash('error_msg', 'Invalid token');
    res.redirect('/2fa');
  }
});

// Route to initiate Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Route to handle Google OAuth callback
app.get('/auth/google/tfa', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/dashboard');
  });

// Middleware to ensure user is authenticated
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    if (req.user.twoFactorEnabled && !req.session.twoFactorAuthenticated) {
      req.session.returnTo = req.originalUrl;
      return res.redirect('/2fa');
    }
    return next();
  }
  req.flash('error_msg', 'Please log in to view this resource');
  res.redirect('/login');
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));