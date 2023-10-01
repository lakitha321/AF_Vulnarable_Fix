const mongoose = require('mongoose')

const StudentGroupSchema = new mongoose.Schema({

    name : {
        type : String,
        unique: true,
        required : true
    },

    member1 : {
        type : String,
        required : true
    },

    member2 : {
        type : String,
    },

    member3 : {
        type : String,
    },

    member4 : {
        type : String,
    },

    supervisor : {
        type : String,
    },

    topic : {
        type : String,
    },

    cosupervisor : {
        type : String,
    },

    panel : {
        type : String,
    },

    marks : {
        type : Number,
    },

});

const StudentGroup = mongoose.model("student group", StudentGroupSchema);

module.exports = StudentGroup;