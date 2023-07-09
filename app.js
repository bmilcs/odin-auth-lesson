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

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// sign up
app
  .route("/sign-up")
  .get((req, res) => res.render("sign-up-form"))
  .post(async (req, res, next) => {
    try {
      const userExists = await User.findOne({ username: req.body.username });

      if (userExists) {
        res.send("user existsss");
        return;
      }

      bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
        if (err) {
          // Handle error if bcrypt hash generation fails
          return next(err);
        }
        const user = new User({
          username: req.body.username,
          password: hashedPassword,
        });
        const result = await user.save();
        res.redirect("/");
      });
    } catch (err) {
      return next(err);
    }
  });

// authentication with passport
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
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

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  }),
);

app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});

app.listen(3000, () => console.log("app listening on port 3000!"));
