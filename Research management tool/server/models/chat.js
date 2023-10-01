const mongoose = require('mongoose');

const ChatSchema = new mongoose.Schema({

    time : {
        type : String,
        required : true
    },

    sender : {
        type : String,
        required : true
    },

    group : {
        type : String,
        required : true
    },

    message : {
        type : String,
        required : true
    },

    role : {
        type : String,
        required : true
    }

});

const Chat = mongoose.model("chat", ChatSchema);

module.exports = Chat;