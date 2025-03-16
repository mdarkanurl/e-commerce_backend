import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
dotenv.config();
import Joi from 'joi';
import User from '../models/user.model.js';
import { sendEmail } from '../config/sendEmail.js';
import { verifyEmailTem } from '../utils/verifyEmailTem.js';
import { generatedRefreshToken } from '../utils/genertedRefreshToken.js';
import { generatedAccessToken } from '../utils/generatedAccessToken.js';
import { uploadImageClodinary } from '../utils/uploadImageClodinary.js';

export const singupUserController = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check all data using Joi
        const schema = Joi.object({
            name: Joi.string().min(3).required(),
            email: Joi.string().email().required(),
            password: Joi.string().min(6).regex(/[a-z]/, 'lowercase').regex(/\d/, 'Number').required(),
        });

        const { error } = schema.validate(req.body, { abortEarly: false, errors: { wrap: { label: "" } } });

        if( error ) {
            const err = error.details.map(msg => msg.message);
            return res.status(400).json({ success: false, message: err });
        }

        const user = await User.findOne({ email });

        if(user) {
            return res.status(401).json({
                success: false,
                message: 'Already signup email, please login'
            });
        }

        const hashPassword = await bcrypt.hash(password, 10);
        
        const save = await User.create({ name, email, password: hashPassword });

        const verifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save._id}`;

        await sendEmail({
            email,
            subject: 'Verify your email',
            html: verifyEmailTem({
                name,
                url: verifyEmailUrl
            })
        });

        return res.status(201).json({ success: true, message: `user created` });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message || error })
    }
}

export const verifyEmailController = async (req, res) => {
    try {
        const { code } = req.query;

        const user = await User.findOne({ _id: code });

        if(!user) {
            return res.status(400).json({
                success: false,
                message: 'Invaild code'
            });
        }

        await User.updateOne({ _id: code }, { verify_email: true });

        res.status(200).json({ success: true, message: 'Email verification done' });
    } catch (error) {
        return res.status(500).json({ success: false, err: error });
    }
}

export const loginController = async (req, res) => {
    try {
        const { email, password } = req.body;

        if(!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and Password have to provide' });
        }

        const user = await User.findOne({ email });

        if(!user || user.
            verify_email === false) {
            return res.status(400).json({
                success: false,
                message: 'User doesn\'t exists, please login first or verify your email'
            });
        }

        if(user.status !== 'Active') {
            return res.status(400).json({
                success: false,
                message: 'Contact to Admin'
            });
        }

        const decodePassword = await bcrypt.compare(password, user.password);

        if(!decodePassword) {
            return res.status(400).json({ success: false, message: 'Incorrect password' });
        }

        const accessToken = await generatedAccessToken(user._id);
        const refreshToken = await generatedRefreshToken(user._id);

        res.cookie('accessToken', accessToken, { httpOnly: true });
        res.cookie('refreshToken', refreshToken, { httpOnly: true });

        res.status(200).json({ success: true, message: 'Login successfully', data: { accessToken, refreshToken } });
    } catch (error) {
        console.log(error);
    }
}

export const logoutController = async (req, res) => {
    try {
        const userId = req.userId;

        res.clearCookie("accessToken", { httpOnly: true });
        res.clearCookie("refreshToken", { httpOnly: true });

        const removeRefreshToken = await User.findByIdAndUpdate(userId, { 
            refresh_token: "" });

        res.status(200).json({ success: true, message: 'Logout successful' });
    } catch (error) {
        console.log(error);
    }
}

export const uploadAvatar = async (req, res) => {
    try {
        const userId = req.userId;
        const image = req.file; // Multer middleware

        const upload = await uploadImageClodinary(image);

        await User.findByIdAndUpdate(userId, { avatar: upload.url });

        res.status(200).json({
            success: true,
            message: 'Avatar uploaded',
            data: { _id: userId, avatar: upload.url }
        });
    } catch (error) {
        console.log(error);
    }
}

export const updateUserDetails = async (req, res) => {
    try {
        const userId = req.userId;
        const { name, password, mobile } = req.body;

        let hashPassword;
        if(password) {
            hashPassword = await bcrypt.hash(password, 10);
        }


        const updateUser = await User.updateOne({ _id: userId }, {
            ...(name && { name: name }),
            ...(password && { password: hashPassword }),
            ...(mobile && { mobile: mobile })
        });

        res.status(200).json({
            success: true,
            message: 'updated user successful',
            data: updateUser
        });
    } catch (error) {
        console.log(error);
    }
}

export const forgotPasswordController = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });

        if(!user) {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid email'
             })
        }

        const OTPCode = Math.floor(100000 + Math.random() * 900000).toString();

        await User.findByIdAndUpdate(user._id, { forgot_password_otp: OTPCode, forgot_password_expiry: (new Date(Date.now() + 5 * 60 * 1000)).toISOString()        });

        await sendEmail({
            email: email,
            subject: 'Forgot password',
            html: `Here's your OTP please user it eithin five min ${OTPCode}`
        });

        res.status(200).json({ success: true, message: 'Check your email' })
    } catch (error) {
        console.log(error);
    }
}

export const verifyForgotPasswordOTP = async (req, res) => {
    try {
        const { email, OTP } = req.body;

        if(!email || !OTP) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP have be provided'
            });
        }

        const user = await User.findOne({
            email: email, 
            forgot_password_otp: OTP,
            forgot_password_expiry: { $gt: Date.now() }
          });
          

        if(!user) {
            return res.status(400).json({ success: false, message: 'Invalid email or OTP or OTP expired' });
        }

        res.status(200).json({ success: true, message: 'OTP verification done, now reset your password', 'reset-Url': 'http://localhost:3000/api/auth/reset-password' });
    } catch (error) {
        console.log(error);
    }
}