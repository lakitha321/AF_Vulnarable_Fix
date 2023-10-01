const express = require('express');
const router = express.Router();
let Request = require("../models/request");

router.route("/add").post(async(req,res)=>{

    const d = new Date();

    const grp = req.body.grp;
    const Staff = req.body.Staff;
    const topic = req.body.topic;
    const time = d.toDateString();
    const status = "Pending...";
    const feedback = '';

    var check;

    const requests = await Request.findOne({grp:grp}).then((requests)=>{
        
        if(requests){
            res.json('Already placed a request!!!');
        }
        else{
            const newRequest = new Request({
                grp,
                Staff,
                time,
                status,
                topic,
                feedback
            })
        
            newRequest.save().then(()=>{
                res.json("Request Added!")
            }).catch((err)=>{
                console.log(err);
            })
        }
    }).catch((err)=>{
        res.json('Already placed a request!!!');
    })

})

router.route("/").get((req,res)=>{

    Request.find().then((Requests)=>{
        res.json(Requests)
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/delete/:id").delete(async (req,res)=>{

    let userId = req.params.id;

    await Request.findByIdAndDelete(userId).then(()=>{
        res.json("Request removed");
    }).catch((err)=>{
        console.log(err);
        res.json("Error");
    })

})

router.route("/get/:email").get(async (req,res)=>{

    let email = req.params.email;

    const requests = await Request.find({Staff:email}).then((requests)=>{
        res.json(requests)
    }).catch((err)=>{
        console.log(err);
        res.json("Error");
    })

})

router.route("/:grp").get(async (req,res)=>{

    let grpName = req.params.grp;

    const requests = await Request.find({grp:grpName}).then((requests)=>{
        res.json(requests)
    }).catch((err)=>{
        console.log(err);
        res.json("Error");
    })

})

router.route("/updateStatus/:id").put(async(req,res)=>{

    const id = req.params.id;

    const status = req.body.status;
    const feedback = req.body.feedback;

    const update = await Request.findByIdAndUpdate(id, {
        status:status,
        feedback:feedback
    }).then(()=>{
        res.json({"msg":"Request Updated", "status":true});
    }).catch((err)=>{
        res.json({"msg":"Request"});
    })

})

module.exports = router;