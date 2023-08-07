//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

mongoose.connect("mongodb://0.0.0.0:27017/userDB", );

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});


const User = mongoose.model("User", userSchema);


app.get("/", function(req, res) {
    res.render("home");
})

app.get("/register", function(req, res) {
    res.render("register");
})

app.get("/login", function(req, res) {
    res.render("login");
})

app.post("/register", function(req, res) {

    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        if(hash) {
            const newUser = new User({
                email: req.body.username,
                password: hash
            });

            try {
                newUser.save();
            } catch(err) {
                console.log(err);
            }
        
            res.render("secrets");
        } else {
            console.log(err);
        } 
    });
})


app.post("/login", function(req, res) {
    const readDb = async () => {

        try {
            const user = await User.findOne({email : req.body.username}).exec();

            if (user) {
                bcrypt.compare(req.body.password, user.password, function(err, result) {
                    if(result) {
                        res.render("secrets");
                    } else {
                        console.log("Wrong password");
                        res.redirect("/login");
                    }
                });            
            } else {
                console.log("No such username");
                res.redirect("/login");
            }
        } catch(err) {
            console.log(err);
            res.redirect("/login");
        }
        
    }

    readDb();
        
})




app.listen( 3000, function() {
    console.log("Server started on port 3000");
})



