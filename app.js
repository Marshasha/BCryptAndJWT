//jshint esversion:6
const express = require("express");
const {promisify} = require('util');
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 12; //the more the harder the work is
const passport = require('passport');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const cookieParser = require('cookie-parser');
const catchAsync = require('./util/catchAsync');
const AppError = require('./util/appError');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true,useUnifiedTopology:true});


const userSchema = {
    email: String,
    password : String
};

const User = new mongoose.model("User", userSchema);

const jwtStrategy = require('./config/passport')(passport);


// This will initialize the passport object on every request
app.use(passport.initialize());

function issueJWT(user){

    const pathToKey = path.join(__dirname, '.', 'id_rsa_priv.pem');
    const PRIV_KEY = fs.readFileSync(pathToKey, 'utf8');

    const _id=user._id;
    const expiresIn = '1d';


    const payload = {
        sub: _id,
        iat: Date.now()
    }

    const signedToken = jwt.sign(payload, PRIV_KEY, { expiresIn: expiresIn, algorithm: 'RS256' });

    return{
        token: "Bearer " + signedToken,
        expires: expiresIn
    }
}


app.get("/", function(req, res){
    res.render("home");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.post("/register", catchAsync(async(req, res, next)=>{

    bcrypt.hash(req.body.password, saltRounds, catchAsync(async(err, hash)=>{
        const newUser = await User.create({
            email: req.body.username,
            password: hash
        });
    
        newUser.save(function(err){
            if(err){
                console.log(err);
            }else{               
               const jwt = issueJWT(newUser);
               console.log(jwt);

               const options = {
                path:"secrets",
                sameSite:true,
                maxAge: 1000 * 60 * 60 * 24, // would expire after 24 hours
                httpOnly: true, // The cookie only accessible by the web server
                }
                res.cookie('jwt',jwt, options) 
                res.render('secrets')

              /* res.json({ success: true, user:newUser, token: jwt.token, expiresIn: jwt.expires }); 
              res.render("secrets"); */
            }
        });
    }));
}));

app.post("/login", function(req, res, next){
   
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email: username}, function(err, foundUser){
       
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                bcrypt.compare(password, foundUser.password, function(err, result){
                    if(result===true){
                        const tokenObject = issueJWT(foundUser);

                        console.log(tokenObject);

                        const options = {
                        path:"secrets",
                     //   secure: true, must be added for the production version, when JWT is sent through HTTPS
                        sameSite:true,
                        maxAge: 1000 * 60 * 60 * 24, // would expire after 24 hours
                        httpOnly: true, // The cookie only accessible by the web server
                        }
                        res.cookie('jwt',tokenObject, options) 
                        res.render('secrets')
                       
                    }
                });
            }
        }
    });
   
});

app.get('/secrets', catchAsync(async(req, res, next)=>{

    /*const token = null;
    if(req && req.cookie){
        token = req.cookie['jwt'];
    } */


    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
        token = req.headers.authorization.split(' ')[1];
    } 
    console.log(token);

    if(!token){
        return next(new AppError('You are not logged in! Please log in to get the access', 401));
    }

    const pathToPubKey = path.join(__dirname, '.', 'id_rsa_pub.pem');
    const PUB_KEY = fs.readFileSync(pathToPubKey, 'utf8');

    const decoded = await promisify(jwt.verify)(token, PUB_KEY);

    console.log(decoded);

    next();
})); 

/*app.get('/secrets', passport.authenticate('jwt', {session:false}), (req, res, next) => {
    res.status(200).json({ success: true, msg: "You are successfully authenticated to this route!"});
}); */

app.listen(3000, function(){
    console.log("Server started on port 3000");
});