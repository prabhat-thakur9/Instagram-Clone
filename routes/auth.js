const express=require('express')
const router=express.Router()
const mongoose=require('mongoose')
const bcrypt=require('bcryptjs')
const jwt=require('jsonwebtoken')
const User=mongoose.model('User')
const requireLogin=require('../middleware/requireLogin')
const crypto =require('crypto')
const nodemailer=require('nodemailer')
const sendgridTransport=require('nodemailer-sendgrid-transport')
const { JWT_SECRET,EMAIL,SENDGRID_API } = require('../config/keys')
const transporter=nodemailer.createTransport(sendgridTransport({
    auth:{
        
        api_key:SENDGRID_API
    }
}))
router.post('/signup',(req,res)=>{
    const {name,email,password,pic}=req.body
    if(!email||!password||!name){
        return res.status(422).json({error:"Please add all the fields"})
    }
    User.findOne({email:email})
        .then((savedUser)=>{
        if(savedUser){
            return res.status(422).json({error:"User already exists"})
        }
        bcrypt.hash(password,12)
        .then(hashedPassword=>{const user=new User({
            email,
            password:hashedPassword,
            name,
            pic
        })
        user.save()
        .then(user=>{
            // transporter.sendMail({
            //     to:user.email,
            //     from:"no-reply@insta.com",
            //     subject:"Signup success",
            //     html:"<h1>Welcome to Instagram</h1>"
            // })
            res.json({message:"Saved Successfully"})
        })
        .catch(err=>{
            console.log(err)
        })
    })})
        
    .catch(err=>{
        console.log(err)
    })
})
router.post('/signin',(req,res)=>{
    const {email,password}=req.body
    if(!email||!password){
        res.status(422).json({error:"Please add properly"})
    }
    User.findOne({email:email})
    .then(savedUser=>{
        if(!savedUser){
            return res.status(422).json({error:"Invalid Credenials"})
        }
        bcrypt.compare(password,savedUser.password)
        .then(doMatch=>{
            if(doMatch){
            // res.json({message:"Successfully Signed In"})
                const token=jwt.sign({_id:savedUser._id},JWT_SECRET)
                const{_id,name,email,followers,following,pic}=savedUser
                res.json({token,user:{_id,name,email,followers,following,pic}})
        }
            else{
                return res.status(422).json({error:"Invalid credentials"})
            }
        })
        .catch(err=>{
            console.log(err)
        })
    })
})

router.post('/reset-password',(req,res)=>{
    crypto.randomBytes(32,(err,buffer)=>{
        if(err){
            console.log(err)
        }
        const token=buffer.toString("hex")
        User.findOne({email:req.body.email})
        .then(user=>{
            if(!user){
                return res.status(422).json({error:"User don't exist"})
            }
            user.resetToken=token
            user.expireToken=Date.now()+3600000
            user.save().then(result=>{
                transporter.sendMail({
                  to:user.email,
                  from:"no-reply@insta.com",
                  subject:"password reset",
                  html:`<p>You are requested for password reset</p>
                  <h5>Click on this<a href="${EMAIL}/reset/${token}"> link </a> to reset password` 
                },(res,err)=>{
                    if(err){
                        console.log(err)
                    }
                    console.log(res)
                })
                res.json({message:"Check your email"})
            })
        })
    })
})

router.post('/new-password',(req,res)=>{
    const newPassword=req.body.password
    const sentToken=req.body.token
    User.findOne({resetToken:sentToken,expireToken:{$gt:Date.now()}})
    .then(user=>{
        if(!user){
            return res.status(422).json({error:"Try Again Session Expired"})
        }
        bcrypt.hash(newPassword,12).then(hashedPassword=>{
            user.password=hashedPassword
            user.resetToken=undefined
            user.expireToken=undefined
            user.save().then((savedUser)=>{
                res.json({message:"password updated"})
            })
        })
    }).catch(err=>{
        console.log(err)
    })
})
module.exports=router