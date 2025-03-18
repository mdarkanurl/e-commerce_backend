import express from 'express';
const router = express.Router();
import uploadImageController from '../controllers/uploadImage.controller.js'
import { auth } from '../middlewares/auth.js';

router.route('/upload')
    .post(auth, uploadImageController)

export default router