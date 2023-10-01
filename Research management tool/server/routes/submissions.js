const express = require('express')
const router = express.Router()
let Submission = require("../models/submission");

router.route("/add").post((req,res)=>{

    const name = req.body.name;
    const desc = req.body.desc;
    const deadline = req.body.deadline;
    const panel = req.body.panel;

    const newSubmission = new Submission({
        name,
        desc,
        deadline,
        panel
    })

    newSubmission.save().then(()=>{
        res.json("Submission Added!")
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/").get((req,res)=>{

    Submission.find().then((Submissions)=>{
        res.json(Submissions)
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/update/:id").put(async (req,res)=>{

    let id = req.params.id;
    const {name, desc, deadline, panel} = req.body;

    const updateSubmission = {
        name,
        desc,
        deadline,
        panel
    }

    const update = await Submission.findByIdAndUpdate(id, updateSubmission).then(()=>{
        res.status(200).send({status: "Submission Updated"})
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with updating data"});
    })

})

router.route("/delete/:id").delete(async (req,res)=>{

    let id = req.params.id;

    await Submission.findByIdAndDelete(id).then(()=>{
        res.json("Submission Deleted");
    }).catch((err)=>{
        console.log(err);
        res.json("Error with delete");
    })

})

router.route("/get/:id").get(async (req,res)=>{

    let id = req.params.id;

    const user = await Submission.findById(id).then((user)=>{
        res.status(200).send({status: "Submission Fetched", user})
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with get user"});
    })

})

module.exports = router;