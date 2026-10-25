import User from "../model/auth.model.js"
import mongoose from "mongoose"
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

export const registerUser = async(req, res) => {
    try{
        const {name, email, password, domain, skills} = req.body
        if(!name || !email || !password){
            return res.status(400).json({
                success : false,
                message : "All feilds are required"
            })
        }
        if(password.length < 8){
            return res.status(400).json({
                success : false,
                message : "Passwords should be atleast 8 characters"
            })
        }
        const existuser = await User.findOne({email})
        if(existuser){
            return res.status(400).json({
                success : false,
                message : "User already exists"
            })
        }
        const hashedPassword = await bcrypt.hash(password, 10)
        const user = await User.create({
            name,
            email,
            password : hashedPassword,
            domain,
            skills
        })
        return res.status(201).json({
            success : true,
            message : "User Created Successfully",
            user
        })
    } catch(e) {
        console.log(e.message)
        return res.status(500).json({
            success : false,
            message : "Internal server error",
        })
    }
}

export const loginUser = async (req, res) => {
    try{
        const {email, password} = req.body
        const user = await User.findOne({email}).select('+password')
        if(!user){
              return res.status(400).json({
                success : false,
                message : "Invalid Email or Password"
            })
        }
        const isMatch = await bcrypt.compare(password, user.password)
        if(!isMatch){
              return res.status(400).json({
                success : false,
                message : "Invalid Password"
            })
        }
        const token = jwt.sign({userID: user._id},process.env.JWT_SECRET)
        return res.status(200).json({
                success : true,
                message : "Login Successful",
                user,
                token
            })
    } catch(e) {
          console.log(e.message)
        return res.status(500).json({
            success : false,
            message : "Internal server error",
        })
    }
}