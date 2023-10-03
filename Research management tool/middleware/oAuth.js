var axios = require("axios");

const tokenEndpoint = "https://dev-0okevvxp6snu1f7e.us.auth0.com/oauth/token";

oAuth = (req, res, next) => {
  var code = req.query.code;

  if(!code) {
    res.status(401).send("Authorization is miissing");
  }

  const params = new URLSearchParams();
  params.append("grant_type", "authorization_code");
  params.append("client_id", "4O0iFf5vtdHiCdVoSbX6JQQ2b66udlDN");
  params.append("client_secret", "sjEHNp2liInLEa_WBxga3PVb-9Heph0wJtV6GGDWEHG2U48yVnEJ9BsdK00IcQOb")
  params.append("code", code);
  params.append("redirect_uri", "http://localhost:3000/");

  axios.post(tokenEndpoint, params)
  .then(response => {
    req.oauth = response.data;
    next();
  })
  .catch(err => {
    console.log(err);
    res.status(403).json(`Reason: ${err.message}`);
  })
}

module.exports = oAuth;