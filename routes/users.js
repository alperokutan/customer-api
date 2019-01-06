const errors = require('restify-errors');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const auth = require('../auth');

module.exports = server => {
    // register user
    server.post('/register', (req, res, next) => {
        const { email, password } = req.body;

        const user = new User({
            email,
            password
        });

        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(user.password, salt, async (err, hash) => {
                // hash password
                user.password = hash;
                // save user
                try {
                    const newUser = await user.save();
                    res.send(201);
                    next();
                } catch (err) {
                    return next(new errors.InternalError(err.message));
                }
            });
        });
    });

    // auth user 
    server.post('/auth', async (req, res, next) => {
        const { email, password } = req.body;
        try {
            // authenticate user
            const user = await auth.authenticate(email, password);
            console.log(user);            
            next();
        } catch (err) {
            // user unauthorized
            return next(new errors.UnauthorizedError(err));
        }
    });
}