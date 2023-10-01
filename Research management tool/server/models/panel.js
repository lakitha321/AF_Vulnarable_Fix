const mongoose = require('mongoose')

const panelSchema = new mongoose.Schema({

    name : {
        type : String,
        required : true
    },

    member1 : {
        type : String,
        required : true
    },
    member2 : {
        type : String,
        required : true
    },

    member3 : {
        type : String,
        required : true
    },

    member4 : {
        type : String,
        required : true
    }

});

const Panel = mongoose.model("panel", panelSchema);

module.exports = Panel;