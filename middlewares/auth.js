import jwt from 'jsonwebtoken';

export const auth = async (req, res, next) => {
    try {
        const token = req.cookies.accessToken || req.header?.authorization?.split(' ')[1];

        if(!token) {
            return res.status(401).json({
                success: false,
                message: 'Token not found, please login first'
            });
        }

        const decode = await jwt.verify(token, process.env.SECRET_KEY_ACCESS_TOKEN)

        if(!decode && decode.expiresIn > Date.now()) {
            return res.status(401).json({
                success: false,
                 message: 'unauthorized access'
            });
        }

        req.userId = decode.id;
        next();
    } catch (error) {
        console.log(error);
    }
}