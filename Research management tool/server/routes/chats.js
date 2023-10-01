const express = require('express');
const router = express.Router();
let Message = require("../models/chat");

router.route("/add").post((req,res)=>{

    var today = new Date();
    var date = today.getFullYear()+'-'+(today.getMonth()+1)+'-'+today.getDate();
    var tim = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
    var time = date+' '+tim;

    const sender = req.body.sender;
    const group = req.body.group;
    const message = req.body.message;
    const role = req.body.role;

    const newMessage = new Message({
        time,
        sender,
        group,
        message,
        role
    })

    newMessage.save().then(()=>{
        res.json("Message Added!")
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/").get((req,res)=>{

    Message.find().then((Messages)=>{
        res.json(Messages)
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/delete/:id").delete(async (req,res)=>{

    let id = req.params.id;

    await Message.findByIdAndDelete(id).then(()=>{
        res.json('Message deleted!');
    }).catch((err)=>{
        console.log(err);
        res.json('error');
    })

})

router.route("/:grp").get(async (req,res)=>{

    let grp = req.params.grp;

    const msg = await Message.find({group:grp}).then((msg)=>{
        res.json(msg);
    }).catch((err)=>{
        console.log(err);
        res.json('error');
    })

})

module.exports = router;