const { json } = require('express');
const express = require('express')
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const router = express.Router()
const bcrypt = require('bcrypt');
const { auth } = require('express-oauth2-jwt-bearer');
const guard = require('express-jwt-permissions')();
let Student = require("../models/student");

const csrf = require('csurf');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

// Initialize csurf middleware
const csrfProtection = csrf({ cookie: true });

// Enable parsing of cookies and request bodies
router.use(cookieParser());
router.use(bodyParser.urlencoded({ extended: true }));

// Sanitize and escape input
const sanitizeInput = (input) => {
    return input.replace(/</g, '&lt;').replace(/>/g, '&gt;');
};

// Import a function to escape HTML characters
function escapeHtml(unsafe) {
    return unsafe.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
  
// Input validation rules
const validationRules = [
    body('name').trim().escape(),
    body('email').trim().isEmail().normalizeEmail(),
    body('age').isInt({ min: 0 }),
    body('gender').isIn(['Male', 'Female', 'Other']),
    body('nic').trim().escape(),
    body('address').trim().escape(),
    body('mobile').isMobilePhone(),
    body('password').trim().escape(),
];

// Load the secret key from an environment variable
const secretKey = process.env.JWT_SECRET;

// Verify that the environment variable is set
if (!secretKey) {
  console.error('JWT_SECRET environment variable is not set.');
  process.exit(1);
}

const jwtCheck = auth({
    audience: 'https://www.oauthnode-api.com',
    issuerBaseURL: 'https://dev-0okevvxp6snu1f7e.us.auth0.com/',
    tokenSigningAlg: 'RS256'
});

// enforce on all endpoints
router.use(jwtCheck);

router.route('/log/:email').post(csrfProtection, async (req, res) => {
  const userEmail = req.params.email;
  const password = req.body.password;

  try {
    const student = await Student.findOne({ email: userEmail });

    if (!student) {
      // If the user does not exist
      return res.status(401).json({ status: false, message: 'User not found' });
    }

    // Compare the entered password with the hashed password
    const passwordMatch = await bcrypt.compare(password, student.password);

    if (passwordMatch) {
      // If the passwords match

      // Create a payload for the JWT (you can include user data or any additional information)
      const payload = {
        id: student._id,
        name: student.name,
        email: student.email,
      };

      // Generate a JWT token with the secret key and set an expiration time
      const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });

      // Send the token as part of the response
      res.json({ status: true, token }); // Include the token in the response
    } else {
      // If the passwords do not match
      res.status(401).json({ status: false, message: 'Incorrect password' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: false, message: 'An error occurred' });
  }
});

// Handle the POST request
router.route('/add').post(guard.check(['write:data']), csrfProtection, validationRules, async (req, res) => {
    try {
      const errors = validationResult(req);
  
      if (!errors.isEmpty()) {
        // Handle validation errors
        return res.status(400).json({ errors: errors.array() });
      }
  
      const name = sanitizeInput(req.body.name);
      const email = sanitizeInput(req.body.email);
      const age = Number(req.body.age);
      const gender = sanitizeInput(req.body.gender);
      const nic = sanitizeInput(req.body.nic);
      const address = sanitizeInput(req.body.address);
      const mobile = Number(req.body.mobile);
      const password = sanitizeInput(req.body.password);
      const groupid = 'Not defined';
  
      // Hash the password using bcrypt
      const hashedPassword = await bcrypt.hash(password, 10); // 10 is the number of salt rounds
  
      const newStudent = new Student({
        name,
        email,
        age,
        gender,
        nic,
        address,
        mobile,
        password: hashedPassword, // Save the hashed password
        groupid,
      });
  
      await newStudent.save();
      res.json('Student Added!');
    } catch (err) {
      console.error(err);
      res.status(500).json('Internal Server Error');
    }
});

// Middleware for parsing cookies and applying CSRF protection
router.route('/')
  .get(guard.check(['read:data']), csrfProtection, (req, res) => {
    // Check if the user is authenticated (assuming you have a user authentication mechanism)
    if (!req.isAuthenticated()) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Fetch the authenticated user's data or session data as needed
    const userData = req.user; // Modify this to access user data from your authentication mechanism

    try {
      // Sanitize the user data before sending it as JSON
      const sanitizedUserData = {
        id: userData.id,
        name: escapeHtml(userData.name),
        email: escapeHtml(userData.email)
      };

      res.json(sanitizedUserData);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'An error occurred' });
    }
});

// Handle the PUT request
router.route('/update/:id').put(guard.check(['read-write:data']), csrfProtection, validationRules, async (req, res) => {
    try {
      const errors = validationResult(req);
  
      if (!errors.isEmpty()) {
        // Handle validation errors
        return res.status(400).json({ errors: errors.array() });
      }
  
      let userId = req.params.id;
      const name = sanitizeInput(req.body.name);
      const email = sanitizeInput(req.body.email);
      const age = Number(req.body.age);
      const gender = sanitizeInput(req.body.gender);
      const nic = sanitizeInput(req.body.nic);
      const address = sanitizeInput(req.body.address);
      const mobile = Number(req.body.mobile);
      const password = sanitizeInput(req.body.password);

      // Hash the password using bcrypt
      const hashedPassword = await bcrypt.hash(password, 10); // 10 is the number of salt rounds
  
      const updateStudent = {
        name,
        email,
        age,
        gender,
        nic,
        address,
        mobile,
        password: hashedPassword, // Save the hashed password
      };
  
      const update = await Student.findByIdAndUpdate(userId, updateStudent);
      res.json({ msg: 'Student Updated', status: true });
    } catch (err) {
      console.error(err);
      res.status(500).json('Internal Server Error');
    }
  });

router.route("/delete/:id").delete(guard.check(['write:data']), csrfProtection, async (req,res)=>{

    let userId = req.params.id;

    await Student.findByIdAndDelete(userId).then(()=>{
        res.json("Student Deleted");
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: "Error with delete"});
    })

})

router.route("/get/:id").get(guard.check(['read:data']), csrfProtection, async (req,res)=>{

    let userId = req.params.id;

    const Students = await Student.findById(userId).then((Students)=>{
        res.json(Students)
    }).catch((err)=>{
        console.log(err);
        res.status(500).send({status: false});
    })

})

router.route("/getgroup/:email").get(guard.check(['read:data']), csrfProtection, async (req,res)=>{

    let useremail = req.params.email;

    const Students = await Student.findOne({email:useremail}).then((Students)=>{
        res.json(Students);
    }).catch((err)=>{
        res.json("error");
    })

})

router.route("/checkgroupvalidity/:email").get(guard.check(['read:data']), csrfProtection, async (req,res)=>{

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

// router.route("/log/:email").post(csrfProtection, async (req,res)=>{

//     let userEmail = req.params.email;
//     const password = req.body.password;

//     const Students = await Student.findOne({email:userEmail}).then((Students)=>{
//         if(password == Students.password){
//             res.json({status: true, Students});
//         }
//         else{
//             res.status(500).send({status: false});
//         }
//     }).catch((err)=>{
//         res.status(500).send({status: false});
//     })

// })

router.route("/updategroup/:email").put(guard.check(['read-write:data']), csrfProtection, async (req,res)=>{

    let userEmail = req.params.email;
    const usergroupid = req.body.groupid;

    const Students = await Student.findOneAndUpdate({email:userEmail}, {groupid:usergroupid}).then((Students)=>{
        res.json({"msg":"Student group registered", "status":true});
    }).catch((err)=>{
        res.json({"msg":"Student group registeration failed", "status":false});
    })

})

module.exports = router;