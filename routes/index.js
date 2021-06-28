var express = require('express');
var router = express.Router();
var bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken")

const swaggerUI = require('swagger-ui-express');
const swaggerDocument = require('../docs/worldhappiness.json');

const secretKey = "anything"

const userAuth = (auth) => {

  let authToken = null;

  // If auth header is missing
  if (!auth) {
    return -10
  }

  // If auth header is malformed (not split Bearer `${token}`)
  if (auth.split(" ").length === 2) {
    authToken = auth.split(" ")[1]
  } else {
    return -8
  }

  try {
    const decoded = jwt.verify(authToken, secretKey)

    // If token has expired
    if (decoded.exp < Date.now()) {
      return -6
    
    // If token has not expired and is a correct token
    } else {
      return true
    }
  // If error occurred while decoding then token is invalid
  } catch(err) {
    return -4
  }
}


/* GET home page. */
router.get('/', function(req, res, next) {
  res.redirect('/docs')
});


// Assignment 2


// Data

// Rankings
router.get("/rankings", function(req,res, next) {

  // Default query parameters
  let queryYear = '%'
  let queryCountry = '%'

  // Check the parameters given to the query
  for (key in req.query) {
    if (key !== "year" && key !== "country") {
      console.log(key)
      res.status(400).json({
        "error": true,
        "message": "Invalid query parameters. Only year and country are permitted."
      })
      return
    }

    // Check that year parameter is correct format and assign query value, else status 400
    if (key == "year") {
      if (isNaN(req.query[key]) || req.query[key].length !== 4) {
        res.status(400).json({
          "error": true,
          "message": "Invalid year format. Format must be yyyy."
        })
        return
      } else {
        queryYear = req.query[key]
      }
    }

    // Check that country parameter is correct format and assign query value, else status 400
    if (key == "country") {
      const containsNumber = /\d/;
      if (containsNumber.test(req.query[key])) {
        res.status(400).json({
          "error": true,
          "message": "Invalid country format. Country query parameter cannot contain numbers."
        })
        return
      } else {
        queryCountry = req.query[key]
      }
    }
  }

  // If all parameter checks succeed, run database query
  req.db.from('rankings').select("rank", "country", "score", "year")
  .where("year", "like", queryYear)
  .andWhere("country", "like", queryCountry)
  .orderBy('year', 'desc')
  .then((rows) => {
  res.json(rows)
  })
  .catch((err) => {
  console.log(err);
  res.json({"Error" : true, "Message" : "Error in MySQL query"})
  })
});

// Countries
router.get("/countries", function(req, res, next) {

  // Check if params have been supplied, if so, send error status then return
  if (Object.keys(req.query).length !== 0 && req.query.constructor === Object) {
    res.status(400).json({
      "error": true,
      "message": "Invalid query parameters. Query parameters are not permitted."
    })
    return
  }

  // Get only distinct countries, to prevent double ups
  req.db.from("rankings").distinct("country").orderBy("country", "asc")
    .then((rows) => {
      // Map only the country name so that an array of strings is returned rather than array of json objects
      res.json(rows.map(row => row.country))
    })
  .catch((err) => {
  console.log(err);
  res.json({"Error" : true, "Message" : "Error in MySQL query"})
  })
});

// Factors
router.get("/factors/:year", function(req,res, next) {

  let queryLimit = null;
  // Default set to % which is a match value, will match all countries unless changed
  let queryCountry = '%'

  // Return different values for different errors, handle the responses accordingly
  let checkAuth = userAuth(req.headers.authorization)

  if (checkAuth === -10) {
    res.status(401).json({"error": true, message : "Authorization header ('Bearer token') not found"})
    return
  } else if (checkAuth === -8) {
    res.status(401).json({"error": true, message : "Authorization header is malformed"})
    return
  } else if (checkAuth === -6) {
    res.status(401).json({"error": true, message : "JWT token has expired"})
    return
  } else if (checkAuth === -4) {
    res.status(401).json({"error": true, message: "Invalid JWT token"})
    return
  }

  // Check the parameters given to the query
  for (key in req.query) {
    if (key !== "limit" && key !== "country") {
      res.status(400).json({
        "error": true,
        "message": "Invalid query parameters. Only year and country are permitted."
      })
      return
    }

    // Check that limit parameter is correct format and assign query value, else status 400
    if (key == "limit") {
      if (isNaN(req.query[key]) || req.query[key] < 0) {
        res.status(400).json({
          "error": true,
          "message": "Invalid limit query. Limit must be a positive number."
        })
        return
      } else {
        queryLimit = req.query[key]
      }
    }

    // Check that country parameter is correct format and assign query value, else status 400
    if (key == "country") {
      const containsNumber = /\d/;
      if (containsNumber.test(req.query[key])) {
        res.status(400).json({
          "error": true,
          "message": "Invalid country format. Country query parameter cannot contain numbers."
        })
        return
      } else {
        queryCountry = req.query[key]
      }
    }
  }


  // Check that the year is a number and of length 4 
  if (!isNaN(req.params.year) && req.params.year.length === 4) {

    // If a valid limit has been supplied, set this to queryLimit (to use in database query)
    if (req.query.limit !== undefined && !isNaN(req.query.limit)) {
      queryLimit = req.query.limit
    }

    // If country is defined, set this to searchCountry
    if (req.query.country !== undefined) {
      queryCountry = req.query.country
    }


    // Make database call, limit will not be valid unless it's been given a correct value
    req.db.from('rankings').select("*")
    .where('year', '=', req.params.year)
    .andWhere('country', 'like', queryCountry)
    .limit(queryLimit)
    .then((rows) => {
      res.status(200).json(rows)
    })
    .catch((err) => {
    console.log(err);
    res.json({"Error" : true, "Message" : "Error in MySQL query"})
    })
    // If year format is incorrect
  } else {
    res.status(400).json({"Error" : true, "Message" : "Invalid year format. Format must be yyyy"})
  }
});


// Authentication

// Register
router.post("/user/register", (req, res) => {

  // Check that both fields have been supplied
  if (req.body.email && req.body.password) {

    // const hashedPass = await bcrypt.hash(req.body.password, 5);
    // Check if user already exists (then response is 409 conflict)
    req.db.from('users').select("*")
    .where("email", "=", req.body.email)
    .then((results) => {
      if (results.length !== 0) {
        res.status(409).json({"error" : true, message : "User already exists"});
        // Else if they don't exist, add them to the database, status 201 success
      } else {
        req.db('users')
        .insert([{
          email: req.body.email,
          passwordHash: bcrypt.hashSync(req.body.password, 10)
        }])
        .then(res.status(201).json({message: "User created"}))
        // Unexpected error, status 500 internal server error
        .catch((err)=>{
          res.status(500).json({message : "Database failed to add user"})
        })
      }
    })
    // If both of the required fields weren't in the body send 400 status
  } else {
    res.status(400).json({ "error" : true, message : "Request body incomplete, both email and password are required" });
  }

});

// Login
router.post("/user/login", (req, res) => {

  // Check that both fields have been supplied
  if (req.body.email && req.body.password) {

    // Check if user email exists
    req.db.from('users').select("*")
    .where("email", "=", req.body.email)
    .then((results) => {
      // If the user email does exist then compare the hashes
      if (results.length === 1) {
        bcrypt.compare(req.body.password, results[0].passwordHash)
        .then((match) => {
          // If the hashes match, return the token
          if (match) {
            const expires_in = 60 * 60 * 24
            const exp = Date.now() + expires_in * 1000
            const userToken = jwt.sign({ email: req.body.email, exp }, secretKey)

            res.status(200).json({
            "token": userToken,
            "token_type": "Bearer",
            "expires_in": expires_in
            })
          // If they don't match, send 401 status
          } else {
            res.status(401).json({
              "error": true,
              "message": "Incorrect email or password"
            })
          }
        })
      // If the user email does not exist, send 401 status
      } else {
        res.status(401).json({
          "error": true,
          "message": "Incorrect email or password"
        })
      }
    })
  // If both of the required fields weren't in the body, send 400 status
  } else {
    res.status(400).json({
      "error": true,
      "message": "Request body incomplete, both email and password are required"
    })
  }
});


// Profile

// GET profile
router.get("/user/:email/profile", function(req,res, next) {

  // Unauthenticated user, default columns
  let selectCols = ["email", "firstName", "lastName"];

  let checkAuth = userAuth(req.headers.authorization)

  // If there was authentication then check for errors, if none, set to all cols
  if (checkAuth === true) {
    selectCols = ["email", "firstName", "lastName", "dob", "address"];
  } else if (checkAuth === -8) {
    res.status(401).json({"error": true, message : "Authorization header is malformed"})
    return
  } else if (checkAuth === -6) {
    res.status(401).json({"error": true, message : "JWT token has expired"})
    return
  } else if (checkAuth === -4) {
    res.status(401).json({"error": true, message: "Invalid JWT token"})
    return
  }

  // Select rows depending on authentication
  req.db.from('users').select(selectCols)
  .where("email", "=", req.params.email)
  .then((cols) => {

  // If there is a result, send a response containing the result
  if (cols.length === 1) {
    res.json(cols[0])
  
  // If there is no result, error with correct status code
  } else {
    res.status(404).json({
      "error": true,
      "message": "User not found"
    })
  }

  // If there is a different error
  })
  .catch((err) => {
  console.log(err);
  res.json({"Error" : true, "Message" : "Error in MySQL query"})
  })
});

// PUT profile
// router.put("/user/:email/profile", (req, res) => {
  

//   // Check auth
//   // if (!userAuth(req.headers.authorization)) {

//   // }
// });

module.exports = router;
