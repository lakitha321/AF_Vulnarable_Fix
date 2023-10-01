const express = require('express')
const router = express.Router()
let Panel = require("../models/panel");
let Staff = require("../models/staff");

router.route("/").post((req,res)=>{

    const name = req.body.name;
    const member1 = req.body.member1;
    const member2 = req.body.member2;
    const member3 = req.body.member3;
    const member4 = req.body.member4;

    const newPanel = new Panel({
        name,
        member1,
        member2,
        member3,
        member4
    })

    newPanel.save().then( async ()=>{
        const update = await Staff.findOneAndUpdate({email:member1}, {panel:"YES"}).then( async ()=>{
            const update = await Staff.findOneAndUpdate({email:member2}, {panel:"YES"}).then( async ()=>{
                const update = await Staff.findOneAndUpdate({email:member3}, {panel:"YES"}).then( async ()=>{
                    const update = await Staff.findOneAndUpdate({email:member4}, {panel:"YES"}).then( async ()=>{
                    }).catch((err)=>{
                        res.json("Error");
                    })
                }).catch((err)=>{
                })
            }).catch((err)=>{
            })
        }).catch((err)=>{
        })
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/").get((req,res)=>{

    Panel.find().then((Panels)=>{
        res.json(Panels)
    }).catch((err)=>{
        console.log(err);
    })

})

router.route("/update/:id").put(async (req,res)=>{

    let panelId = req.params.id;
    const {name, age, gender} = req.body;

    const updatePanel = {
        name,
        age,
        gender
    }

    const update = await Panel.findByIdAndUpdate(panelId, updatePanel).then(()=>{
        res.status(200).send({status: "panel Updated"})
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with updating data"});
    })

})

router.route("/:id").delete(async (req,res)=>{

    let panelId = req.params.id;

    // const panel = await Panel.findById(panelId).then((panel)=>{
    // }).catch((err)=>{
    // })

    const panel = await Panel.findByIdAndDelete(panelId).then( async (panel)=>{
        res.json({status: "panel Deleted", panel});
        const m1 = panel.member1;
        const m2 = panel.member2;
        const m3 = panel.member3;
        const m4 = panel.member4;
        await Staff.findOneAndUpdate({email:m1}, {panel:""}).then(async()=>{
            await Staff.findOneAndUpdate({email:m2}, {panel:""}).then(async()=>{
                await Staff.findOneAndUpdate({email:m3}, {panel:""}).then(async()=>{
                    await Staff.findOneAndUpdate({email:m4}, {panel:""}).then(async()=>{

                    });
                });
            });
        });
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with delete"});
    })

})

router.route("/get/:id").get(async (req,res)=>{

    let panelId = req.params.id;

    const panel = await Panel.findById(panelId).then((panel)=>{
        res.status(200).send({status: "panel Fetched", panel})
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with get panel"});
    })

})

module.exports = router;