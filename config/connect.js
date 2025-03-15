import dotenv from "dotenv";
dotenv.config();
import mongoose from "mongoose";

if(!(process.env.MONGODB_URL)) {
    throw new Error(
        'Please provide MONGODB_URL in the .env file'
    );
}

export const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URL);
        console.log('MongoDB connected');
    } catch (error) {
        console.log(error);
        process.exit(1);
    }
}