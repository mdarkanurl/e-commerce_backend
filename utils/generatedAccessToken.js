import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

export const generatedAccessToken = async (userId) => {
    try {
        const token = await jwt.sign({ id: userId }, process.env.SECRET_KEY_ACCESS_TOKEN, { expiresIn: '1h' });

        return token
    } catch (error) {
        console.log(error);
    }
}