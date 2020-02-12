/* eslint-disable strict */
/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */
'use strict';


function errorHandler(err, req, res, next) {
  res.status(500);
  res.Message = 'server error';
  res.json({ error: err });
}

module.exports = errorHandler;