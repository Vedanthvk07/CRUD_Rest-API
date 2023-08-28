const asyncHandler=require("express-async-handler");
const bcrypt=require("bcrypt"); //npm i bcrypt
const jwt=require("jsonwebtoken");
const User=require("../models/userModel");
//@desc Register a user
//@route Get /api/user/register
//@access public

const registerUser=asyncHandler(async(req,res)=>{
    const {username,email,password}=req.body;
    if(!username|| !email || !password){
        res.status(400);
        throw new Error("all fields are mandatory!");
    }
    const userAvailable=await User.findOne({email});
    if(userAvailable){
        res.status(400);
        throw new Error("user already registered");
    }
    
    // hash password
    const hashedPassword=await bcrypt.hash(password,10);
    console.log("hashed:",hashedPassword);
    const user=await User.create({
        username,
        email,
        password:hashedPassword,
    });

    console.log(`user created ${user}`);
    if(user){
        res.status(201).json({id:user.id,email:user.email});

    }
    else{
        res.status(400);
        throw new Error("user not valid!")
    }
    res.json({message:"register the user"});
}
);

//@desc Login a user
//@route Get /api/user/login
//@access public

const loginUser=asyncHandler(async(req,res)=>{
    const {email,password}=req.body;
    if(!email || !password){
        res.status(400);
        throw new Error("All fields are mandatory");
    }
    const user=await User.findOne({email});
    //compare pass with hashedpass

    if(user && (await bcrypt.compare(password,user.password))){
        const accessToken=jwt.sign({
            user:{
                username:user.username,
                email:user.email,
                id:user.id,
            },
        }, process.env.ACCESS_TOKEN_SECRET,
        {expiresIn:"10m"}
        );
        res.status(200).json({
            accessToken
        });
    }
    else{
        res.status(401);
        throw new Error("Email or password not valid");
    }
   // res.json({message:"login user"});
});

//@desc current user
//@route Get /api/user/current
//@access private

const currentUser=asyncHandler(async(req,res)=>{
    res.json(req.user);
});

module.exports={
    registerUser,
    loginUser,
    currentUser,
};