const { json } = require('express');
const express = require('express')
const router = express.Router()
let Admin = require("../models/admin");

router.route("/add").post(async (req,res)=>{

    const name = req.body.name;
    const email = req.body.email;
    const nic = req.body.nic;
    const mobile = Number(req.body.mobile);
    const firstpassword = req.body.firstpassword;
    const secondpassword = req.body.secondpassword;

    const newAdmin = new Admin({
        name,
        email,
        nic,
        mobile,
        firstpassword,
        secondpassword
    })

    await newAdmin.save().then(()=>{
        res.json("New Admin Added!")
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/").get(async (req,res)=>{

    await Admin.find().then((Admins)=>{
        res.json(Admins)
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/update/:id").put(async (req,res)=>{

    let id = req.params.id;
    const name = req.body.name;
    const email = req.body.email;
    const nic = req.body.nic;
    const mobile = Number(req.body.mobile);
    const firstpassword = req.body.firstpassword;
    const secondpassword = req.body.secondpassword;

    const updateAdmin = {
        name,
        email,
        nic,
        mobile,
        firstpassword,
        secondpassword
    }

    const update = await Admin.findByIdAndUpdate(id, updateAdmin).then(()=>{
        res.json({"msg":"Admin Updated", "status":true});
    }).catch((err)=>{
        res.json("Error");
    })

})

router.route("/delete/:id").delete(async (req,res)=>{

    let userId = req.params.id;

    await Admin.findByIdAndDelete(userId).then(()=>{
        res.json("Admin Deleted");
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with delete"});
    })

})

router.route("/get/:id").get(async (req,res)=>{

    let userId = req.params.id;

    const Admins = await Admin.findById(userId).then((Admins)=>{
        res.json(Admins)
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: false});
    })

})

router.route("/firstlog/:email").post(async (req,res)=>{

    let userEmail = req.params.email;
    const password1 = req.body.firstpassword;

    const Admins = await Admin.findOne({email:userEmail}).then((Admins)=>{
        if(password1 == Admins.firstpassword){
            res.json({status: true});
        }
        else{
            res.status(500).send({status: false});
        }
    }).catch((err)=>{
        res.status(500).send({status: false});
    })

})

router.route("/secondlog/:email").post(async (req,res)=>{

    let userEmail = req.params.email;
    const password1 = req.body.secondpassword;

    const Admins = await Admin.findOne({email:userEmail}).then((Admins)=>{
        if(password1 == Admins.secondpassword){
            res.json({status: true, Admins});
        }
        else{
            res.status(500).send({status: false});
        }
    }).catch((err)=>{
        res.status(500).send({status: false});
    })

})

module.exports = router;