var express = require('express');
var router = express.Router();

const { createUser, login } = require('./controller/userController')

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});


router.post('/create-user', createUser);

router.get('/login', login)

module.exports = router;
