'use strict';

// Passport Strategy configuration

const passport = require('passport');
const passportLocal = require('passport-local');
const passportGithub = require('passport-github');
const bcrypt = require('bcryptjs');

const LocalStrategy = passportLocal.Strategy;
const GithubStrategy = passportGithub.Strategy;

const User = require('./models/user');

passport.serializeUser((user, callback) => {
  callback(null, user._id);
});

passport.deserializeUser((id, callback) => {
  User.findById(id)
    .then((user) => {
      callback(null, user);
    })
    .catch((error) => {
      callback(error);
    });
});

passport.use(
  new GithubStrategy(
    {
      clientID: process.env.GITHUB_API_CLIENT_ID,
      clientSecret: process.env.GITHUB_API_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/authentication/github-callback',
      scope: 'user:email',
    },
    (accessToken, refreshToken, profile, callback) => {
      console.log(profile);
      const profileDetails = {
        name: profile.displayName,
        email: profile.emails.length ? profile.emails[0].value : null,
        photo: profile._json.avatar_url,
        githubId: profile.id,
      };
      const githubId = profileDetails.githubId;
      User.findOne({ githubId })
        .then((user) => {
          if (!user) {
            return User.create({
              name: profileDetails.name,
              email: profileDetails.email,
              photo: profileDetails.photo,
              githubId: profileDetails.githubId,
            });
          }
          return Promise.resolve(user);
        })
        .then((user) => {
          callback(null, user);
        })
        .catch((error) => {
          callback(error);
        });
    }
  )
);

passport.use(
  'sign-up',
  new LocalStrategy({}, (username, password, callback) => {
    bcrypt
      .hash(password, 10)
      .then((hashAndSalt) => {
        return User.create({
          username,
          passwordHash: hashAndSalt,
        });
      })
      .then((user) => {
        callback(null, user);
      })
      .catch((error) => {
        callback(error);
      });
  })
);

passport.use(
  'sign-in',
  new LocalStrategy({}, (username, password, callback) => {
    let user;
    User.findOne({ username })
      .then((document) => {
        if (document) {
          user = document;
          return bcrypt.compare(password, user.passwordHash);
        }
        return Promise.reject(new Error('That username does not exist'));
      })
      .then((result) => {
        if (result) {
          callback(null, user);
        } else {
          return Promise.reject(new Error('Password is incorrect.'));
        }
      })
      .catch((error) => {
        callback(error);
      });
  })
);
