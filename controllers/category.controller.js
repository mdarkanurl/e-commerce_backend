import Category from '../models/category.model.js';

export const addCategoryController = async (req, res) => {
    try {
        const { name, image } = req.body;

        if(!name || !image) {
            return res.statsu(400).json({
                success: false,
                message: 'Name and image have to give'
            });
        }

        const saveCategory = await Category.create({ name, image });

        if(!saveCategory) {
            return res.statsu(500).json({ success: false, message: 'Server error, please try aging' });
        }

        return res.statsu(201).json({ success: false, message: 'Category created' });
    } catch (error) {
        console.log(error);
    }
}