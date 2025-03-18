import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import helmet from 'helmet';
import { connectDB } from './config/connect.js';
import userRouter from './routes/user.route.js';
import uploadRouter from './routes/upload.route.js';
import categoryRouter from './routes/category.route.js';
dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan()); 
app.use(helmet());

// Router
app.use('/api/auth', userRouter);
app.use('/api/category', categoryRouter);
app.use('/api/upload', uploadRouter);

app.listen(PORT, async () => {
    console.log(`http://localhost:${PORT}`);
    connectDB();
});