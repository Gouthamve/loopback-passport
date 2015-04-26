var loopback = require('loopback');
var boot = require('loopback-boot');
var hbs = require('hbs')
var app = module.exports = loopback();
var passport = require('passport');
var crypto = require("crypto");
/*
 * body-parser is a piece of express middleware that
 *   reads a form's input and stores it as a javascript
 *   object accessible through `req.body`
 *
 */
var bodyParser = require('body-parser');

/**
 * Flash messages for passport
 *
 * Setting the failureFlash option to true instructs Passport to flash an
 * error message using the message given by the strategy's verify callback,
 * if any. This is often the best approach, because the verify callback
 * can make the most accurate determination of why authentication failed.
 */
var flash      = require('express-flash');
// Set up the /favicon.ico
app.use(loopback.favicon());

// request pre-processing middleware
app.use(loopback.compress());

// -- Add your pre-processing middleware here --


var path = require('path');
app.set('views', "/Users/goutham/adiStuff/fb-univ/server/views");
app.set('view engine', 'hbs');


// boot scripts mount components like REST API
boot(app, __dirname);

// to support JSON-encoded bodies
app.use(bodyParser.json());
// to support URL-encoded bodies
app.use(bodyParser.urlencoded({
  extended: true
}));

// The access token is only available after boot
app.use(loopback.token({
  model: app.models.accessToken,
  cookies: ['accessToken']
}));

app.use(loopback.cookieParser("SECRET"));
app.use(loopback.session({
  secret: 'kitty',
  saveUninitialized: true,
  resave: true
}));
// We need flash messages to see passport errors
app.use(flash());

//---------------- Passport Config -------------//
var LocalStrategy   = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var student = app.models.student;

// =========================================================================
// passport session setup ==================================================
// =========================================================================
// required for persistent login sessions
// passport needs ability to serialize and unserialize users out of session

// used to serialize the user for the session
passport.serializeUser(function(student, done) {
    done(null, student.id);
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    student.findById(id, function(err, student) {
        done(err, student);
    });
});

// =========================================================================
// LOCAL SIGNUP ============================================================
// =========================================================================
// we are using named strategies since we have one for login and one for signup
// by default, if there was no name, it would just be called 'local'

passport.use('local-signup', new LocalStrategy({
  // by default, local strategy uses username and password, we will override with email
  usernameField : 'email',
  passwordField : 'password',
  passReqToCallback : true // allows us to pass back the entire request to the callback
}, function(req, email, password, done) {
  // asynchronous
  // User.findOne wont fire unless data is sent back
  process.nextTick(function() {
  // find a user whose email is the same as the forms email
  // we are checking to see if the user trying to login already exists
  student.findOne({where: { 'email' :  email }}, function(err, user) {
    // if there are any errors, return the error
    if (err) {
      console.log(err)
      return done(err);
    }
    // check to see if theres already a user with that email
    if (user) {
      return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
    } else {
      // if there is no user with that email
      // create the user
      student.create({"email": email, "password": password}, function(err, student){
        if(err) {
          console.log(err)
          throw err
        }
        return done(null, student);
      })
    }
  });});
}));

// =========================================================================
// LOCAL LOGIN =============================================================
// =========================================================================
// we are using named strategies since we have one for login and one for signup
// by default, if there was no name, it would just be called 'local'

passport.use('local-login', new LocalStrategy({
  // by default, local strategy uses username and password, we will override with email
  usernameField : 'email',
  passwordField : 'password',
  passReqToCallback : true // allows us to pass back the entire request to the callback
},
function(req, email, password, done) { 
  // callback with email and password from our form
  student.findOne({where: { 'email' :  email }}, function(err, studentProfile){
    if(err)
      return done(err)
    if (student) {
      var userProfile = studentProfile.toJSON();
      delete userProfile.password;
    } else {
      return done(null, false, {message: 'Incorrect email.'});
    }
    //Try logging in the user
    student.login({"email": email, "password": password}, function(err, token){
      if(err) {
        console.log(err)
        return done(err)
      }
      userProfile["accessToken"] = token;
      return done(null, userProfile);
    })
  })  
}));

// route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {
    // if user is authenticated in the session, carry on 
    if (req.isAuthenticated())
        return next();

    // if they aren't redirect them to the home page
    res.redirect('/');
}

// =========================================================================
// FACEBOOK LOGIN ==========================================================
// =========================================================================


var facebookAuth = app.get("facebookAuth")
passport.use(new FacebookStrategy({
  // pull in our app id and secret from our auth.js file
  clientID        : facebookAuth.clientID,
  clientSecret    : facebookAuth.clientSecret,
  callbackURL     : facebookAuth.callbackURL
},
// facebook will send back the token and profile
function(token, refreshToken, profile, done) {
  // asynchronous
  process.nextTick(function() {
    algorithm = 'sha1';
    encoding = 'hex';
    hmacKey = profile.id;
    hmac = crypto.createHmac(algorithm, hmacKey);
    passwordHash = hmac.digest(encoding);
    // find the user in the database based on their facebook id
    student.findOne({where: { 'fbId' : profile.id }}, function(err, studentProfile) {
      // if there is an error, stop everything and return that
      // ie an error connecting to the database
      if (err)
        return done(err);

      // if the user is found, then log them in
      if (studentProfile) {
        var userProfile = studentProfile.toJSON();
        student.login({
          "email": profile.emails[0].value, 
          "password": passwordHash}, function(err, aToken){
            if(err)
              console.log(err)
            console.log(aToken)
            return done(null, userProfile); // user found, return that user
        });
      } else {
        // if there is no user found with that facebook id, create them
        student.create({
          "email": profile.emails[0].value,
          "password": passwordHash,
          "fbId": profile.id,
          "fbToken": token,
          "fbEmail": profile.emails[0].value,
          "fbName": profile.name.givenName + ' ' + profile.name.familyName
        }, function(err, studentProfile){
          if(err) {
            console.log(err)
            throw err
          }
          return done(null, studentProfile);
        })
      }
    });
  });
}));


app.use(passport.initialize());
app.use(passport.session());
//----------------------------------------------//

var ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;

app.get('/', function(req, res, next) {
  res.render('index');  
});

app.post('/signup', passport.authenticate('local-signup', {
  successRedirect : '/profile', // redirect to the secure profile section
  failureRedirect : '/signup', // redirect back to the signup page if there is an error
  failureFlash : true // allow flash messages
}));

app.get('/signup', function(req, res){
  res.render('signup');
});

app.get('/profile', isLoggedIn, function(req, res){
  res.render('profile');
});

app.get('/login', function(req, res){
  res.render('login');
});

app.post('/login', passport.authenticate('local-login', {
  successRedirect : '/profile', // redirect to the secure profile section
  failureRedirect : '/login', // redirect back to the signup page if there is an error
  failureFlash : true // allow flash messages
}));

app.get('/auth/facebook', passport.authenticate('facebook', { scope : 'email' }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', {
  successRedirect : '/profile',
  failureRedirect : '/'
}));

app.start = function() {
  // start the web server
  return app.listen(function() {
    app.emit('started');
    console.log('Web server listening at: %s', app.get('url'));
  });
};

// start the server if `$ node server.js`
if (require.main === module)
  app.start();
