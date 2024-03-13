import { Router } from "express";
import {
  changeCurrentPassword,
  getCurrentUser,
  getUserChannelProfile,
  getWatchHistory,
  loginUser,
  logoutUser,
  refreshAccessToken,
  registerUser,
  updateAccountDetails,
  updateAvatar,
  updateCoverImage,
} from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJwt } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(
  upload.fields([
    { name: "avatar", maxCount: 1 },
    { name: "coverImage", maxCount: 1 },
  ]),
  registerUser
);

router.route("/login").post(loginUser);
router.route("/refresh-token").post(refreshAccessToken);

//secured routes
router.route("/logout").post(verifyJwt, logoutUser);
router.route("/change-password").post(verifyJwt, changeCurrentPassword);
router.route("/current-user").get(verifyJwt, getCurrentUser);
router.route("/updte-details").patch(verifyJwt, updateAccountDetails);

router
  .route("/change-avatar")
  .patch(verifyJwt, upload.single("avatar"), updateAvatar);

router
  .route("/change-cover-image")
  .patch(verifyJwt, upload.single("coverImage"), updateCoverImage);

router.route("/c/:username").get(verifyJwt, getUserChannelProfile);

router.route("/watch-history").get(verifyJwt, getWatchHistory);

export default router;
