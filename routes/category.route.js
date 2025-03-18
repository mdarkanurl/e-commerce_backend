import express from 'express';
import { addCategoryController } from '../controllers/category.controller.js';
import { auth } from '../middlewares/auth.js';
const router = express.Router();

router.route('/add-category')
    .post(auth, addCategoryController)

export default router