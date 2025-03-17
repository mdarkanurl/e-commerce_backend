import express from 'express';
const router = express.Router();
import { forgotPasswordController, loginController, logoutController, resetPassword, singupUserController, updateUserDetails, uploadAvatar, verifyEmailController, verifyForgotPasswordOTP } from "../controllers/user.controller.js";
import { auth } from '../middlewares/auth.js';
import { upload } from '../middlewares/multer.js';

router.route('/signup')
    .get()
    .post(singupUserController);


router.route('/verify-email')
    .get()
    .post(verifyEmailController);


router.route('/login')
    .get()
    .post(loginController);


router.route('/logout')
    .get(auth, logoutController)
    .post();


router.route('/upload-avatar')
    .put(auth, upload.single('avatar'), uploadAvatar)


router.route('/update-user')
    .put(auth, updateUserDetails)


router.route('/forgot-password')
    .post(forgotPasswordController)


router.route('/verify-forgot-password')
    .put(verifyForgotPasswordOTP)


router.route('/reset-password')
    .put(resetPassword)

export default router