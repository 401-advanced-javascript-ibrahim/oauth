/* eslint-disable new-cap */
/* eslint-disable no-unused-vars */
/* eslint-disable strict */
'use strict';

const express = require('express');
const router = express.Router();

const User = require('./users.js');
const authMiddleware = require('./auth-middleware.js');
const oauthMiddleware = require('./oauth/oauth-middleware.js');

router.post('/signup', signup);
router.post('/signin', authMiddleware, signin);
router.get('/user', getUser);
router.get('/oauth', oauthMiddleware, oauth);

function signup(req, res, next) {
  let user = new User(req.body);
  console.log('ssss', user);
  user.save()
    .then(user => {
      console.log('asdsad', user);
      req.token = user.tokenGenerator(user);
      req.user = user;
      res.status(200).send(req.token);
    })
    .catch(next);
}

function signin(req, res, next) {
  res.send(req.token);
}

function getUser(req, res, next) {
  User.list()
    .then(data => {
      res.status(200).json(data);
    });
}

function oauth(re, res, next) {
  res.status(200).send(req.token);
}

module.exports = router;