const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const {authenticateToken,} = require('../middlewares/authMiddleware');
const validator = require('../validator/router-validation')

router.post('/signup',validator.signupSchemaValidator,authController.signup);
router.post('/verify-otp',validator.verifyotpSchemaValidator, authController.verifyOtp);
router.post('/login',validator.loginSchemaValidator, authController.login);
router.post('/resend-otp',validator.resendOtpSchemaValidator, authController.resendOtp);
router.get('/verify-email/:token', authController.verifyEmail);
router.post('/logout',authenticateToken,authController.logout)
router.post('/resendVerifyEmail',authController.resendVerificationEmail)
router.post('/forget-password',validator.forgotPasswordSchemaValidator,authController.forgetPassword)
router.get('/reset-password',authController.getResetPassword)
router.post('/reset-password',validator.resetPasswordSchemaValidator,authController.resetPassword)
router.post('/change-password',validator.changePasswordSchemaValidator,authenticateToken,authController.changePassword)


module.exports = router;
