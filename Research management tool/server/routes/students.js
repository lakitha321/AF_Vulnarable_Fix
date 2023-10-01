const { json } = require('express');
const express = require('express')
const router = express.Router()
let Student = require("../models/student");

router.route("/add").post(async (req,res)=>{

    const name = req.body.name;
    const email = req.body.email;
    const age = Number(req.body.age);
    const gender = req.body.gender;
    const nic = req.body.nic;
    const address = req.body.address;
    const mobile = Number(req.body.mobile);
    const password = req.body.password;
    const groupid = "Not defined";

    const newStudent = new Student({
        name,
        email,
        age,
        gender,
        nic,
        address,
        mobile,
        password,
        groupid
    })

    await newStudent.save().then(()=>{
        res.json("Student Added!");
    }).catch((err)=>{
        res.json(err)
    })

})

router.route("/").get(async (req,res)=>{

    await Student.find().then((Students)=>{
        res.json(Students)
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/update/:id").put(async (req,res)=>{

    let userId = req.params.id;
    const name = req.body.name;
    const email = req.body.email;
    const age = Number(req.body.age);
    const gender = req.body.gender;
    const nic = req.body.nic;
    const address = req.body.address;
    const mobile = Number(req.body.mobile);
    const password = req.body.password;

    const updateStudent = {
        name,
        email,
        age,
        gender,
        nic,
        address,
        mobile,
        password
    }

    const update = await Student.findByIdAndUpdate(userId, updateStudent).then(()=>{
        res.json({"msg":"Student Updated", "status":true});
    }).catch((err)=>{
        res.json("Error");
    })

})

router.route("/delete/:id").delete(async (req,res)=>{

    let userId = req.params.id;

    await Student.findByIdAndDelete(userId).then(()=>{
        res.json("Student Deleted");
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with delete"});
    })

})

router.route("/get/:id").get(async (req,res)=>{

    let userId = req.params.id;

    const Students = await Student.findById(userId).then((Students)=>{
        res.json(Students)
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: false});
    })

})

router.route("/getgroup/:email").get(async (req,res)=>{

    let useremail = req.params.email;

    const Students = await Student.findOne({email:useremail}).then((Students)=>{
        res.json(Students);
    }).catch((err)=>{
        res.json("error");
    })

})

router.route("/checkgroupvalidity/:email").get(async (req,res)=>{

    let useremail = req.params.email;

    const Students = await Student.findOne({email:useremail, groupid:"Not defined"}).then((Students)=>{
        if(useremail == Students.email && Students.groupid == "Not defined"){
            res.json(true);
        }else{
            res.json(false);
        }
    }).catch((err)=>{
        res.json(false);
    })

})

router.route("/log/:email").post(async (req,res)=>{

    let userEmail = req.params.email;
    const password = req.body.password;

    const Students = await Student.findOne({email:userEmail}).then((Students)=>{
        if(password == Students.password){
            res.json({status: true, Students});
        }
        else{
            res.status(500).send({status: false});
        }
    }).catch((err)=>{
        res.status(500).send({status: false});
    })

})

router.route("/updategroup/:email").put(async (req,res)=>{

    let userEmail = req.params.email;
    const usergroupid = req.body.groupid;

    const Students = await Student.findOneAndUpdate({email:userEmail}, {groupid:usergroupid}).then((Students)=>{
        res.json({"msg":"Student group registered", "status":true});
    }).catch((err)=>{
        res.json({"msg":"Student group registeration failed", "status":false});
    })

})

module.exports = router;