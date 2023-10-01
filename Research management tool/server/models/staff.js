const mongoose = require('mongoose')

const StaffSchema = new mongoose.Schema({

    name : {
        type : String,
        required : true
    },

    email : {
        type : String,
        unique: true,
        required : true
    },

    age : {
        type : Number,
        required : true
    },

    gender : {
        type : String,
        required : true
    },

    nic : {
        type : String,
        unique: true,
        required : true
    },

    address : {
        type : String,
        required : true
    },

    mobile : {
        type : Number,
        unique: true,
        required : true
    },

    password : {
        type : String,
        unique: true,
        required : true
    },

    role : {
        type : String,
    },

    research : {
        type : String,
    },

    panel : {
        type : String,
    }

});

const Staff = mongoose.model("staff", StaffSchema);

module.exports = Staff;