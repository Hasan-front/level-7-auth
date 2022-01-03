//jshint esversion:6
require('dotenv').config()
const express= require("express");
const bodyParser= require("body-parser")
const ejs= require("ejs")
const mongoose=require("mongoose")
const session = require('express-session')
const passport = require("passport")
const passportLocalMongoose=require("passport-local-mongoose")
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate")
const FacebookStrategy = require("passport-facebook").Strategy;

const app = express()

app.use(express.static("public"))
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({
	extended: true
}))

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
  }))
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB")

const userSchema = new mongoose.Schema({
	email:String,
	password:String,
	googleId:String,
	facebookId:String,
	secret:String

});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const user=new mongoose.model("user",userSchema)


passport.use(user.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  user.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
  	console.log(profile)
    user.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
  	console.log(profile)
    user.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res) {
	res.render("home")
})

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
  );


app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook')
  );

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res) {
	res.render("login")
})
app.get("/register",function(req,res) {
	res.render("register")
})
app.get("/secrets",function(req,res) {
	user.find({secret:{$ne:null}},function(err,founduser) {
		if (err) {
			console.log(err)
		} else {
			if (founduser) {
				res.render("secrets", {userwithsecret:founduser})
			}
		}
	})
})
app.get("/submit",function(req,res){
	if (req.isAuthenticated()) {
		res.render("submit")
	} else {
		res.redirect("/login")
	}
})
app.post("/submit",function(req,res) {
	 const usersecret = req.body.secret;

	 user.findOne(req.user._id,function(err,user) {
	 	if (err) {
	 		console.log(err)
	 	}
	 	else{
	 		if (user) {
	 			user.secret = usersecret;
	 			user.save(function() {
	 				res.redirect("/secrets")
	 			})
	 		}
	 	}
	 })

})
app.get("/logout",function(req,res) {
	req.logout()
	res.redirect("/")
})
app.post("/register",function(req,res) {

user.register({username : req.body.username }, req.body.password, function(err, user) {
	if (err) {
		console.log(err)
		res.redirect("/register")
	}
	else
	{
		passport.authenticate("local")(req,res,function() {
			res.redirect("/secrets")
		})
	}
})	
	
})
app.post("/login", function(req, res){
  //check the DB to see if the username that was used to login exists in the DB
  user.findOne({username: req.body.username}, function(err, foundUser){
    //if username is found in the database, create an object called "user" that will store the username and password
    //that was used to login
    if(foundUser){
    const user3 = new user({
      username: req.body.username,
      password: req.body.password
    });
      //use the "user" object that was just created to check against the username and password in the database
      //in this case below, "user" will either return a "false" boolean value if it doesn't match, or it will
      //return the user found in the database
      passport.authenticate("local", function(err, user){
        if(err){
          console.log(err);
        } else {
          //this is the "user" returned from the passport.authenticate callback, which will be either
          //a false boolean value if no it didn't match the username and password or
          //a the user that was found, which would make it a truthy statement
          if(user){
            //if true, then log the user in, else redirect to login page
            req.login(user3, function(err){
            res.redirect("/secrets");
            });
          } else {
            res.redirect("/login");
          }
        }
      })(req, res);
    //if no username is found at all, redirect to login page.
    } else {
      //user does not exists
      res.redirect("/login")
    }
  });
});

app.listen(3000, function(req,res) {
	console.log("welcome to port 3000")
})
