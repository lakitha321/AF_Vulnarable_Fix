const express = require('express');
const helmet = require('helmet');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const app = express();
require('dotenv').config();

const studentRouter = require("./routes/students");

const PORT = process.env.PORT || 8070;

// Configure CSP (Content-Security-Policy)
const cspConfig = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "trusted-scripts.example.com"],
    frameAncestors: ["'none'"], // CSP with frame-ancestors directive
  },
};

// Define a list of allowed origins (domains)
const allowedOrigins = ['http://localhost:3000/', 'https://localhost:8081/'];

app.use(helmet.contentSecurityPolicy(cspConfig));

app.use(helmet.xssFilter());

// Set X-Frame-Options header to SAMEORIGIN
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});

// app.use(cors());
// Configure CORS middleware with the allowed origins
app.use(cors({
  origin: function (origin, callback) {
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
}));

// Suppress the X-Powered-By header
app.disable('x-powered-by');

// Configure X-Content-Type-Options header
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// Middleware for parsing cookies and request bodies
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

// Initialize csurf middleware
const csrfProtection = csrf({ cookie: true });

// Use csrfProtection middleware for all routes
app.use(csrfProtection);

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

app.use("/student", studentRouter);

app.listen(PORT, () => {
  console.log(`Server is up and running at port no: ${PORT}`)
});