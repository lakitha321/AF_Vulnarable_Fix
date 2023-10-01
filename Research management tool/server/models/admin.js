const mongoose = require('mongoose')

const AdminSchema = new mongoose.Schema({

    name : {
        type : String,
        required : true
    },

    email : {
        type : String,
        required : true
    },

    nic : {
        type : String,
        required : true
    },

    mobile : {
        type : String,
        required : true
    },

    firstpassword : {
        type : String,
        required : true
    },

    secondpassword : {
        type : String,
        required : true
    }
});

const Admin = mongoose.model("admin", AdminSchema);

module.exports = Admin;