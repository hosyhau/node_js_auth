var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var bcrypt = require('bcryptjs');
var VerifyToken = require(__root + 'auth/VerifyToken');
var jwt = require('jsonwebtoken');
var config = require('../config');
router.use(bodyParser.urlencoded({ extended: true }));
var User = require('./User');

router.get('/',VerifyToken,function(req,res){
    User.find({},function(err,users){
        if(err) return res.status(500).json({message:'Failed to load data.'});
        return res.json(users);
    });
});

router.get('/get-by-id',VerifyToken,function(req,res){
    User.findById(req._id,function(err,user){
        if(err) return res.status(500).json({message:'Internal server'});
        if(!user) return res.status(404).json({message:'No User can be found'});
        
        res.status(200).json(user);
    });
});

router.delete('/delete-by-id/:id',VerifyToken,function(req,res){
    User.findByIdAndRemove(req.params.id,function(err,user){
        if(err) return res.status(500).json({message:'There was a problem to delete user.'});
        bcrypt.compare(guess,user.password,function(err,res){
            if(err) throw err;
            console.log(res);
        });
        console.log(user);
        res.status(200).json({message:`user `+user.username+` is deleted`});
    });
});

router.post('/create-user',function(req,res){
    var hashPassword = bcrypt.hashSync(req.body.password,8);
    var userReq = {
        name:req.body.name,
        email:req.body.email,
        password:hashPassword
    };
    User.create(userReq,function(err,user){
            if(err) res.status(500).json({message:'there was a problem to create a new user.'});
            // create a token for user.
            var token = jwt.sign({id:user._id},config.secret,{
                expiresIn:84000
            });
            res.status(200).json({auth:true,token:token});
        }
    )
});

router.put('/update-profile',VerifyToken,function(req,res,next){
    User.findByIdAndUpdate(req.body._id,req.body,{new: true},function(err,user){
        if(err) return res.status(500).json({message:'there was a problem to update user'});

        res.status(200).json(user);
    });
});



module.exports = router;