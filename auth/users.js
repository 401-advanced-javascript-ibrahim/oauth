/* eslint-disable strict */
'use strict';

require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const SECRET = process.env.SECRET;

const users = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
});

users.pre('save', async function () {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 5);
    }
    return Promise.reject();
});

users.statics.authenticater = function (auth) { /// I got confused to use eathier statcs or methods for this function  
    let query = { username: auth.user };
    return this.findOne(query)
        .then(user => {
            return user.passwordComparator(auth.pass);
        })
        .catch(console.error);
};

users.methods.passwordComparator = function (pass) {
    return bcrypt.compare(pass, this.password)
        .then(valid => {
            return valid ? this : null
        });
};

users.methods.tokenGenerator = function (user) {
    let token = {
        id: user._id,
    };
    return jwt.sign(token, SECRET);
};

users.statics.list = async function () {
    let result = await this.find({});
    return result;
}

users.statics.authenticateToken = async function (token) {
    try {
        let tokenObject = jwt.verify(token, process.env.SECRET);

        if (tokenObject.username) {
            return Promise.resolve(tokenObject);
        } else {
            return Promise.reject();
        }
    } catch (e) {
        return Promise.reject();
    };
}

module.exports = mongoose.model('users', users);