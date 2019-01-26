const axios = require('axios');

const { authenticate, jwtKey } = require('../auth/authenticate');

// require knex file in order to get access to database
const db = require('../database/dbConfig.js');

// require bcrypt, jwt dependencies
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// generate a token
function generateToken(user) {
  const payload = {
    username: user.username
  };
  const options = {
    expiresIn: '1h',
  };
  return jwt.sign(payload, jwtKey, options);
}

module.exports = server => {
  server.post('/api/register', register);
  server.post('/api/login', login);
  server.get('/api/jokes', authenticate, getJokes);
};

function register(req, res) {
  // implement user registration
  const creds = req.body;
  const hash = bcrypt.hashSync(creds.password, 14);
  creds.password = hash;
  if (req.body.username && req.body.password) {
    db('users')
      .insert(creds)
      .then(ids => {
        const id = ids[0]
        db('users')
          .where('id', id)
          .then(user => {
            const token = generateToken(user);
            res
              .status(201)
              .send(token);
          })
          .catch(err => {
            res
              .status(500)
              .json({message: 'The user could not be registered at this time.'});
          })
      })
      .catch(err => {
        res
          .status(500)
          .json({message: 'The user could not be registered at this time.'});
      });
  }
  else {
    res
      .status(400)
      .json({message: 'Please provide a username and password to register.'});
  }
}

function login(req, res) {
  // implement user login
  const creds = req.body;
  if (req.body.username && req.body.password) {
    db('users')
      .where('username', creds.username)
      .then(user => {
        if (user.length && bcrypt.compareSync(creds.password, user[0].password)) {
          const token = generateToken(user);
          res
            .send(token);
        }
        else {
          res
            .status(401)
            .json({message: 'You shall not pass!!!'});
        }
      })
      .catch(err => {
        res
          .status(500)
          .json({message: 'The user could not be logged in at this time.'});
      })
  }
  else {
    res
      .status(400)
      .json({message: 'Please provide a username and a password to log in.'});
  }

}

function getJokes(req, res) {
  const requestOptions = {
    headers: { accept: 'application/json' },
  };

  axios
    .get('https://icanhazdadjoke.com/search', requestOptions)
    .then(response => {
      res.status(200).json(response.data.results);
    })
    .catch(err => {
      res.status(500).json({ message: 'Error Fetching Jokes', error: err });
    });
}
