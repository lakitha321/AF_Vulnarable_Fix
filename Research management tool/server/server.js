const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
require('dotenv').config();

const personRouter = require("./routes/persons");
const studentRouter = require("./routes/students");
const staffRouter = require("./routes/staffs");
const adminRouter = require("./routes/admins");
const submissionRouter = require("./routes/submissions");
const studentSubmissionRouter = require("./routes/studentSubmissions");
const fileRoute = require("./routes/templates");
const groupRoute = require("./routes/studentgroups");
const requestRoute = require("./routes/requests");
const chat = require("./routes/chats");
const panel = require("./routes/panels");

const PORT = process.env.PORT || 8070;

app.use(cors());
app.use(bodyParser.json());

const URI = process.env.MONGODB_URL;

mongoose.connect(URI, {
  useCreateIndex: true,
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false
});

const connection = mongoose.connection
connection.once("open", () => {
  console.log('MongoDB Connection Success!!!')
});

app.use("/person", personRouter);
app.use("/student", studentRouter);
app.use("/staff", staffRouter);
app.use("/admin", adminRouter);
app.use("/submission", submissionRouter);
app.use("/studentsubmission", studentSubmissionRouter);
app.use("/assignment", fileRoute);
app.use("/studentgroup", groupRoute);
app.use("/request", requestRoute);
app.use("/chat", chat);
app.use("/panel", panel);

app.listen(PORT, () => {
  console.log(`Server is up and running at port no: ${PORT}`)
});