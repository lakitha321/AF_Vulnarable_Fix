var express = require("express");
var axios = require("axios");
var port = process.env.PORT || 3001;
var oAuth = require("./oAuth");
var app = express();

const endpoint1 = "http://localhost:8070/";

app.use(oAuth);

app.get("/", async (req, res) => {
  try {
    const { access_token } = req.oauth;

    const response = await axios({
      method: "get",
      url: endpoint1,
      headers: { Authorization: `Bearer ${access_token}` },
    });
    res.json(response.data);
  } catch (error) {
    console.log(error);
    if (error.response.status === 401) {
      res.status(401).json("Unauthorized to access data");
    } else if (error.response.status === 403) {
      res.status(403).json("Permission denied");
    } else {
      res.status(500).json("Whoops, something went wrong");
    }
  }
});

const endpoint2 = "http://localhost:8070/getgroup/";

app.use(oAuth);

app.get("/", async (req, res) => {
  try {
    const { access_token } = req.oauth;

    const response = await axios({
      method: "get",
      url: endpoint2,
      headers: { Authorization: `Bearer ${access_token}` },
    });
    res.json(response.data);
  } catch (error) {
    console.log(error);
    if (error.response.status === 401) {
      res.status(401).json("Unauthorized to access data");
    } else if (error.response.status === 403) {
      res.status(403).json("Permission denied");
    } else {
      res.status(500).json("Whoops, something went wrong");
    }
  }
});

app.listen(port, () => console.log("Middleware started..."));
