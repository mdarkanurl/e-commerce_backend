import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import User from '../models/user.model.js';
dotenv.config();

export const generatedRefreshToken = async (userId) => {
    try {
        const token = await jwt.sign({ id: userId }, process.env.SECRET_KEY_REFRESH_TOKEN, { expiresIn: '30d' });

        await User.updateOne({ _id: userId }, { refresh_token: token })

        return token
    } catch (error) {
        console.log(error);
    }
}