const mongoose = require('mongoose')

const RequestSchema = new mongoose.Schema({

    grp : {
        type : String,
        required : true
    },

    Staff : {
        type : String,
        required : true
    },

    time : {
        type : String,
        required : true
    },

    status : {
        type : String,
        required : true
    },

    topic : {
        type : String
    },

    feedback : {
        type : String
    }

});

const Request = mongoose.model("request", RequestSchema);

module.exports = Request;