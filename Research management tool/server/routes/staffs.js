const { json } = require('express');
const express = require('express')
const router = express.Router()
let Staff = require("../models/staff");

router.route("/add").post(async (req,res)=>{

    const name = req.body.name;
    const email = req.body.email;
    const age = Number(req.body.age);
    const gender = req.body.gender;
    const nic = req.body.nic;
    const address = req.body.address;
    const mobile = Number(req.body.mobile);
    const password = req.body.password;
    const role = "Staff member";
    const research = "Not defined";

    const newStaff = new Staff({
        name,
        email,
        age,
        gender,
        nic,
        address,
        mobile,
        password,
        role,
        research
    })

    await newStaff.save().then(()=>{
        res.json("Staff Added!");
    }).catch((err)=>{
        res.json("Error");
    })

})

router.route("/").get(async (req,res)=>{

    await Staff.find().then((Staffs)=>{
        res.json(Staffs)
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

    const updateStaff = {
        name,
        email,
        age,
        gender,
        nic,
        address,
        mobile,
        password
    }

    const update = await Staff.findByIdAndUpdate(userId, updateStaff).then(()=>{
        res.json({"msg":"Staff Updated", "status":true});
    }).catch((err)=>{
        res.json("Error");
    })

})

router.route("/updaterole/:id").put(async (req,res)=>{

    let userId = req.params.id;
    const role1 = req.body.role;
    const research1 = req.body.research;

    const update = await Staff.findByIdAndUpdate(userId, {role:role1, research:research1}).then(()=>{
        res.json("Role updated");
    }).catch((err)=>{
        res.json("Error");
    })

})

router.route("/delete/:id").delete(async (req,res)=>{

    let userId = req.params.id;

    await Staff.findByIdAndDelete(userId).then(()=>{
        res.json("Staff Deleted");
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with delete"});
    })

})

router.route("/get/:id").get(async (req,res)=>{

    let userId = req.params.id;

    const Staffs = await Staff.findById(userId).then((Staffs)=>{
        res.json(Staffs)
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: false});
    })

})

router.route("/getcosup").get(async (req,res)=>{

    const Staffs = await Staff.find({role:'Co-supervisor'}).then((Staffs)=>{
        res.json(Staffs)
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: false});
    })

})

router.route("/getsup").get(async (req,res)=>{

    const Staffs = await Staff.find({role:'Supervisor'}).then((Staffs)=>{
        res.json(Staffs)
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: false});
    })

})

router.route("/log/:email").post(async (req,res)=>{

    let userEmail = req.params.email;
    const password = req.body.password;

    const Staffs = await Staff.findOne({email:userEmail}).then((Staffs)=>{
        if(password == Staffs.password){
            res.json({status: true, Staffs});
        }
        else{
            res.status(500).send({status: false});
        }
    }).catch((err)=>{
        res.status(500).send({status: false});
    })

})

router.route("/addtopanel/:email").put(async (req,res)=>{

    let email = req.params.email;

    const update = await Staff.findOneAndUpdate({email:email}, {panel:"YES"}).then(()=>{
        res.json("Added");
    }).catch((err)=>{
        res.json("Error");
    })

})

router.route("/removefrompanel/:email").put(async (req,res)=>{

    let email = req.params.email;

    const update = await Staff.findOneAndUpdate({email:email}, {panel:"NO"}).then(()=>{
        res.json("Removed");
    }).catch((err)=>{
        res.json("Error");
    })

})

module.exports = router;