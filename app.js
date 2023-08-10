//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: 'This is our little secret.',
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://0.0.0.0:27017/userDB", );

const userSchema = new mongoose.Schema({
    googleId: String,
    email: String,
    password: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user.id);
    });
});

passport.deserializeUser(async function(id, cb) {
    const user = await User.findById(id).exec();
    if(user) {
        return cb(null, user);
    }
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
    res.render("home");
})

app.get("/register", function(req, res) {
    res.render("register");
})

app.get("/login", function(req, res) {
    res.render("login");
})

app.get('/auth/google',function (req, res) {
    return passport.authenticate('google', { scope: ['profile'] })(req, res);
});

app.get("/auth/google/secrets", 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get("/secrets",async function(req, res) {
    try {
        const foundUsers = await User.find({ "secret": {$ne: null}}).exec();
    
        if(foundUsers) {
            res.render("secrets", {usersWithSecrets: foundUsers});
        }
    }
    catch(err) {
        console.log(err);
    }
    
});

app.get("/submit", function(req, res) {
    if(req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", async function(req, res) {
    const submittedSecret = req.body.secret;

    console.log(req.user);

    try {
        const foundUser = await User.findById(req.user.id).exec();

        if (foundUser) {
            foundUser.secret = submittedSecret;
            await foundUser.save();
            console.log("Secret saved successfully");
        } else {
            console.log("User not found, secret not saved");
        }

        res.redirect("/secrets"); // Redirect to the secrets page or another appropriate destination
    } catch (error) {
        console.error("Error saving secret:", error);
        res.status(500).send("An error occurred while saving the secret.");
    }
});



app.get("/logout", function(req, res) {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

app.post("/register", function(req, res) {

    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if(err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });

});


app.post("/login", function(req, res) {
     
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err) {
        if (err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
})




app.listen( 3000, function() {
    console.log("Server started on port 3000");
})



