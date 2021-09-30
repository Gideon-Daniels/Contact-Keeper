const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next) {
    //Get token from header , Also check to see if there is a token in the header
    const token = req.header('x-auth-token');

    // Check if not token
    if (!token) {
        return res.status(401).json({ msg:'No token, authorization denied'});
    }

    try {
        // verify the token if it exist and load the payload
        const decoded = jwt.verify(token, config.get('jwtSecret'));
        // send the payload so we can have access to it in the user route
        req.user = decoded.user;
        next();
    } catch (err) {
        // if it doesn't verify
        res.status(401).json({ msg: 'Token is not valid'});
    }
}