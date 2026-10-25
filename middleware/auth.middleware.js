import jwt from "jsonwebtoken";
import User from "../model/auth.model.js";

export const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        msg: "Token is required",
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.userID);

    if (!user) {
      return res.status(401).json({
        msg: "User not found",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.log("Auth middleware error:", error.message);

    return res.status(401).json({
      msg: "Invalid or expired token",
    });
  }
};