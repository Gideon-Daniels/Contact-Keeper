const mongoose = require('mongoose');

const UserSchema = mongoose.Schema({
    role: {
        type: String,
        required: true,
        default: "user",
    },
    name: {
        type: String,
        required:true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    date: {
        type:Date,
        default: Date.now
    }
});

module.exports = mongoose.model('user', UserSchema)