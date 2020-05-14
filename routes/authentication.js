'use strict';

const { Router } = require('express');
const authenticationRouter = Router();

const passport = require('passport');

authenticationRouter.get('/sign-up', (req, res, next) => {
  res.render('authentication/sign-up');
});

authenticationRouter.post(
  '/sign-up',
  passport.authenticate('sign-up', {
    successRedirect: '/private',
    failureFlash: 'Could not sign-up',
  })
);

authenticationRouter.get('/sign-in', (req, res, next) => {
  res.render('authentication/sign-in');
});

authenticationRouter.get(
  '/github',
  passport.authenticate('github', {
    successRedirect: '/',
    failureRedirect: '/error',
  })
);

authenticationRouter.get(
  '/github-callback',
  passport.authenticate('github', {
    successRedirect: '/',
    failureRedirect: '/error',
  })
);

authenticationRouter.post(
  '/sign-in',
  passport.authenticate('sign-in', {
    successRedirect: '/',
    failureRedirect: '/error',
  })
);

authenticationRouter.post('/sign-out', (req, res, next) => {
  req.logout();
  res.redirect('/');
});

module.exports = authenticationRouter;
