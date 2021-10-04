const User = require('../model/User');
const bcrypt = require('bcryptjs')

function checkForNumberAndSymbol(target){
    if(target.match(/[!`\-=@#$%^&*()\[\],.?":;{}|<>1234567890]/g)){
        return true
    }
    else{
        return false
    }
}

function isEmail(target){
    if(target.match(/^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/g)){
        return true
    }
    else{
        return false
    }
}

function isEmpty(target){
    if(target.length  === 0){
        return true
    }
    else{
        return false
    }
}

function checkSymbol(target){
    if(target.match(/[!`\-=@#$%^&*()\[\],.?":;{}|<>]/g)){
        return true
    }
    else{
        return false
    }
}

function checkPaswordStrength(target) {
    var strongRegex = new RegExp(
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[_!@#$%^=-{}[]&*|:;'?.<>`~])(?=.{8,})"
    );
    return !strongRegex.test(target);
}

async function createUser(req, res) {
    const { firstName, lastName, username, email, password } = req.body
    let body = req.body
    let errObj = {}

    for(let key in body){
        if(isEmpty(body[key])){
            errObj[`${key}`] = `${key} cannot be empty`
        }
    }

    if(checkForNumberAndSymbol(firstName)){
        errObj.firstName = 'First name cannot have special characters or number'
    }

    if(checkForNumberAndSymbol(lastName)){
        errObj.lastName = 'Last name cannot have special characters or number'
    }
    
    if(checkSymbol(username)){
        errObj.username = 'Username cannot have special characters'
    }

    if(!isEmail(email)){
        errObj.email = 'Email invalid'
    }

    if(checkPaswordStrength(password)){
        errObj.password = 'invalid password'
    }
    

    if (Object.keys(errObj).length > 0){
        return res.status(500).json({
            message: 'error',
            error: errObj
        })
    }

    try {
        let salt = await bcrypt.genSalt(10);
        let hashed = await bcrypt.hash(password, salt)
        const createdUser = new User({
            firstName,
            lastName,
            username,
            email,
            password: hashed 
        });

        let savedUser = await createdUser.save();

        res.json({ message: "SUCCESS", payload: savedUser })
    } 
    catch(error) {
        res
            .status(500)
            .json({ message: "FAILURE", error: error.message })
    }
}

module.exports = {
    createUser,
}