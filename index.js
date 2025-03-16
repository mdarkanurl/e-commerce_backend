import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import helmet from 'helmet';
import { connectDB } from './config/connect.js';
import router from './routes/user.route.js';
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
app.use('/api/auth', router);

app.listen(PORT, async () => {
    console.log(`http://localhost:${PORT}`);
    connectDB();
});