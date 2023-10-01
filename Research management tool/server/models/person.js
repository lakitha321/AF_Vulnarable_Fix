const mongoose = require('mongoose')
//const Schema = new mongoose.Schema;

const PersonSchema = new mongoose.Schema({

    name : {
        type : String,
        required : true
    },

    age : {
        type : Number,
        required : true
    },

    gender : {
        type : String,
        required : true
    }

});

const Person = mongoose.model("person", PersonSchema);

module.exports = Person;