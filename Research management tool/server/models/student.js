const mongoose = require('mongoose')

const StudentSchema = new mongoose.Schema({

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

    groupid : {
        type : String,
    }

});

const Student = mongoose.model("student", StudentSchema);

module.exports = Student;