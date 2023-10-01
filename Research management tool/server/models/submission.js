const mongoose = require('mongoose')

const SubmissionSchema = new mongoose.Schema({

    name : {
        type : String,
        required : true
    },

    desc : {
        type : String,
        required : true
    },

    deadline : {
        type : String,
        required : true
    },

    panel : {
        type : String,
        required : true
    }

});

const Submission = mongoose.model("submission", SubmissionSchema);

module.exports = Submission;