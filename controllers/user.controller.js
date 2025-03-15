import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
dotenv.config();
import Joi from 'joi';
import User from '../models/user.model.js';
import { sendEmail } from '../config/sendEmail.js';
import { verifyEmailTem } from '../utils/verifyEmailTem.js';
import { generatedRefreshToken } from '../utils/genertedRefreshToken.js';
import { generatedAccessToken } from '../utils/generatedAccessToken.js';

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

        if(!user) {
            return res.status(400).json({
                success: false,
                message: 'User doesn\'t exists, please login first'
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