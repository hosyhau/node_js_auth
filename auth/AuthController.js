var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');

var verifyToken = require('./VerifyToken');

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
var User = require('../user/User');

var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require("../config");

router.post('/register',function(req,res){
    var hashPassword = bcrypt.hashSync(req.body.password,8);
    User.create(
        {
            name:req.body.name,
            email:req.body.email,
            password:hashPassword
        },
        function(err,user){
            if(err) res.status(500).json({message:'there was a problem to create a new user.'});
            // create a token for user.
            var token = jwt.sign({id:user._id},config.secret,{
                expiresIn:84000
            });
            res.status(200).json({auth:true,token:token});
        }
    )
});

router.post('/login',function(req,res){
    User.findOne({email:req.body.email},function(err,user){
        if(err) return res.status(500).json({message:'internal server'});
        if(!user) return res.status(400).json({message:'No user found'});
        var password = bcrypt.compareSync(req.body.password,user.password);
        if(!password) return res.status(401).json({auth:true,token:null});
        var token = jwt.sign({id:user._id},config.secret,{
            expiresIn:84000
        });
        res.status(200).json({auth:true,token:token});

    });
});

router.get('/me',verifyToken,function(req,res,next){
    User.findById(req._id,{password:0},function(err,user){
        if(err) return res.status(500).json({message:'there was a problem to find user information.'});
        if(!user) return res.status(400).json({message:'can not find user infor '});
        res.status(200).json(user);
    });
});

router.get('/logout', function(req, res) {
    res.status(200).send({ auth: false, token: null });
  });

  module.exports = router;