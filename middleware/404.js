/* eslint-disable strict */
/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */
'use strict';
function notFoundHandler(req, res, next) {
  res.status(404);
  res.message = 'Ops!!, NOT FOUND';
  res.json({ error: 'NOT FOUND'});
}

module.exports = notFoundHandler;