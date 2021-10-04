const User = require('../model/User');
const bcrypt = require('bcryptjs')
const validator = require('validator')


async function createUser(req, res) {
    const { firstName, lastName, username, email, password } = req.body
    let body = req.body
    let errObj = {}


    if(!validator.isAlpha(firstName)){
        errObj.firstName = 'First name cannot have special characters or numbers'
    }

    if(!validator.isAlpha(lastName)){
        errObj.lastName = 'Last name cannot have special characters or numbers'
    }

    if(!validator.isAlphanumeric(username)){
        errObj.username = 'Username cannot have any special characters'
    }

    if(!validator.isEmail(email)){
        errObj.email = 'Invalid email! Plaese try a differnt one'
    }

    if(!validator.isStrongPassword(password)){
        errObj.password = 'Weak password! Please try a different one'
    }
    
    for(let key in body){
        if(validator.isEmpty(body[key])){
            errObj[`${key}`] = `${key} cannot be empty`
        }
    }

    if (Object.keys(errObj).length > 0){
        return res.status(500).json({
            message: "error",
            error: errObj
        })
    }

    try{
        let salt = await bcrypt.genSalt(10)
        let hashed = await bcrypt.hash(password, salt)
        const createdUser = new User({
            firstName,
            lastName,
            username,
            email,
            password: hashed,
        })
        let savedUser = await createdUser.save()

        res.json({message: 'success', payload: savedUser})
    }
    catch(error){
        res.status(500).json({message: 'failed', error: error.message})
    }
}

async function login(req, res){
    const {email, password} = req.body
    
    let errObj = {}

    if(validator.isEmpty(email)){
        errObj.email = 'Please enter yout email'
    }

    if(validator.isEmpty(password)){
        errObj.password = 'Please enter yout password'
    }

    if(!validator.isEmail(email)){
        errObj.email = 'Please enter a valid email'
    }

    if (Object.keys(errObj).length > 0){
        return res.status(500).json({
            message: "error",
            error: errObj
        })
    }

    let foundUser = await User.findOne({email: email})

    try{
        if(!foundUser){
            return res.status(500).json({
                message: 'error',
                error: 'user does not exist. PLease sign up'
            })
        }
        else{
            let comparedPassword = await bcrypt.compare(password, foundUser.password);

            if(!comparedPassword){
                return res.status(500).json({
                    message: 'error',
                    error: 'please check your email and password'
                })
            }
            else{
                return res.json({
                    message: 'success'
                })
            }
        }
    }
    catch(e){
        res.status(500).json({
            message: 'error',
            error: e.message
        })
    }
    
}

module.exports = {
    createUser,
    login
}