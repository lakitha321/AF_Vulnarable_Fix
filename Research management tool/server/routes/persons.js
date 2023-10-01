const express = require('express')
const router = express.Router()
let Person = require("../models/person");

router.route("/add").post((req,res)=>{

    const name = req.body.name;
    const age = Number(req.body.age);
    const gender = req.body.gender;

    const newPerson = new Person({
        name,
        age,
        gender
    })

    newPerson.save().then(()=>{
        res.json("Person Added!")
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/").get((req,res)=>{

    Person.find().then((persons)=>{
        res.json(persons)
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/update/:id").put(async (req,res)=>{

    let userId = req.params.id;
    const {name, age, gender} = req.body;

    const updatePerson = {
        name,
        age,
        gender
    }

    const update = await Person.findByIdAndUpdate(userId, updatePerson).then(()=>{
        res.status(200).send({status: "User Updated"})
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with updating data"});
    })

})

router.route("/delete/:id").delete(async (req,res)=>{

    let userId = req.params.id;

    await Person.findByIdAndDelete(userId).then(()=>{
        res.status(200).send({status: "User Deleted"});
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with delete"});
    })

})

router.route("/get/:id").get(async (req,res)=>{

    let userId = req.params.id;

    const user = await Person.findById(userId).then((user)=>{
        res.status(200).send({status: "User Fetched", user})
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with get user"});
    })

})

module.exports = router;