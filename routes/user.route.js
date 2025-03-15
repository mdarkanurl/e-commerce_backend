import express from 'express';
const router = express.Router();
import { loginController, singupUserController, verifyEmailController } from "../controllers/user.controller.js";

router.route('/signup')
    .get()
    .post(singupUserController);


router.route('/verify-email')
    .get()
    .post(verifyEmailController);


router.route('/login')
    .get()
    .post(loginController);

export default router