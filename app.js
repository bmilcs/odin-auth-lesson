/////// app.js

const express = require("express");
require("dotenv").config();
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcryptjs");

// database setup
const mongoDb = process.env.MONGODB;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  }),
);

// express setup
const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

// passport authentication
// server session: stored in memory (not suitable for production)
// client session: stored in a cookie
app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// called when user is authenticated
// determines which data of the user object should be stored in the session
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

// called when a request is made & passport needs to retrieve user info from the session
// retrieves user's info based on the stored id
// makes user object available on `req.user` in subsequent middleware/route handlers
passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// passport local strategy: username/password & db
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      // find user by username
      // if no user found, return error message
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }

      // if user found, compare supplied pw with hashed pw in db
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords match! log user in
          return done(null, user);
        } else {
          // passwords do not match!
          return done(null, false, { message: "Incorrect password" });
        }
      });
    } catch (err) {
      return done(err);
    }
  }),
);

// sign up
app
  .route("/sign-up")
  .get((req, res) => res.render("sign-up-form"))
  .post(async (req, res, next) => {
    try {
      // prevent duplicate usernames
      const userExists = await User.findOne({ username: req.body.username });
      if (userExists) {
        res.send("user exists!");
        return;
      }

      // hash password: salt = 10 extra characters to add to pw
      bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
        // handle error if bcrypt hash generation fails
        if (err) {
          return next(err);
        }

        // create new user
        const user = new User({
          username: req.body.username,
          password: hashedPassword,
        });

        // save new user & redirect
        await user.save();
        res.redirect("/");
      });
    } catch (err) {
      return next(err);
    }
  });

// log in handling
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  }),
);

// log out handling
app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// index route
app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});

app.listen(3000, () => console.log("app listening on port 3000!"));
