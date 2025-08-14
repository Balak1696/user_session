const { User,Session,PasswordResetToken} = require('../models');
const bcryptHelper = require('../utils/bcryptHelper');
const jwtHelper = require('../utils/jwtHelper');
const emailHelper = require('../utils/emailHelper');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const { where } = require('sequelize');
const { generateOTP } = require('../utils/otpHelper');
const { sendOtpEmail } = require('../utils/emailHelper')
dotenv.config();
const { Op } = require('sequelize');
const MAX_SESSIONS_PER_USER = parseInt(process.env.MAX_SESSIONS_PER_USER, 10) || 2;
const RESET_TOKEN_TTL_MINUTES = process.env.RESET_TOKEN_TTL_MINUTES || 15;

const signup = async (req, res) => {
  try {
    const { firstname, lastname, email, password, terms} = req.body;

    if(!firstname || !lastname || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (!terms) {
      return res.status(400).json({ message: 'You must accept the terms and conditions to register' });
    }
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    // const roleData = await Role.findOne({ where: { name: 'superadmin' } });
    // if (!roleData) {
    //  res.status(400).json({ message: 'role not found' });
    // }
    const hashedPassword = await bcryptHelper.hashPassword(password);
    const otp = generateOTP();
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
    const newUser = await User.create({
      firstname,
      lastname,
      email,
      password: hashedPassword,
      isVerified: false,
      otp,
      otpExpiresAt,
      //roleId: roleData.id,
      terms,
      isActive: false,
      last_LoggedIn: null,
      
    });
    // const tokenPayload = { id: newUser.id, email: newUser.email, firstname: newUser.firstname, lastname: newUser.lastname };
    // const token = jwtHelper.generateToken(tokenPayload, process.env.JWT_SECRET, '10m');
    // const verificationUrl = `${process.env.VERIFICATION_URL}/verify-email/${token}`;
    // await emailHelper.verificationEmail(email, verificationUrl, firstname);
    // return res.status(200).json({
    //   message: 'User created successfully. Please verify your email.',
    //   user: { id: newUser.id, firstname: newUser.firstname, email: newUser.email, token },
    // });
    await sendOtpEmail(email, otp, firstname);

    return res.status(200).json({
      message: 'Signup successful. OTP sent to your email. Please verify to activate account.',
      newUser
    });
  } catch (error) {
    console.log(error)
    return res.status(500).json({message:'server error'});
  }
};
const resendVerificationEmail = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.isVerified) {
      return res.status(400).json({ error: 'User is already verified' });
    }
    const token = jwtHelper.generateToken({ email }, process.env.JWT_SECRET, '2m');
    const verificationUrl = `${process.env.VERIFICATION_URL}/verify-email/${token}`;
    await emailHelper.verificationEmail(email, verificationUrl, user.firstname);
    return res.status(200).json({ message: 'Verification email sent successfully' });
  } catch (error) {
    return res.status(500).json(res, error, 'Resend verification email error');
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const MAX_DEVICES = parseInt(process.env.MAX_SESSIONS_PER_USER || 2);

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (!user.isVerified) {
      return res.status(403).json({ message: 'Email not verified. Please verify OTP to login.' });
    }

    if (!user.isActive) {
      return res.status(403).json({ message: 'Your account is inactive. Contact admin.' });
    }

    const isPasswordValid = await bcryptHelper.comparePassword(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

   const activeSessions = await Session.findAll({ where: { userId: user.id } });
   if (activeSessions.length >= MAX_SESSIONS_PER_USER) {
     const oldestSession = await Session.findOne({ where: { userId: user.id }, order: [['createdAt', 'ASC']] });
     if (oldestSession) {
       await oldestSession.destroy();
     }
   }
  
    const tokenPayload = { id: user.id, email: user.email };
    const token = jwtHelper.generateToken(tokenPayload,'1d');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 1 day
    await Session.create({
      userId: user.id,
      token,
      ipAddress: req.ip,
      deviceInfo: req.headers['user-agent'],
      expiresAt,
    });

   await user.update({ last_LoggedIn: new Date() });
    return res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        firstname: user.firstname,
        lastname: user.lastname
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ message: 'Server error' });
  }
};
const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and OTP are required.' });
    }

    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: 'User is already verified.' });
    }

    if (!user.otp || !user.otpExpiresAt) {
      return res.status(400).json({ message: 'OTP not generated. Please request a new OTP.' });
    }

    if (user.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP.' });
    }

    if (new Date() > user.otpExpiresAt) {
      return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }

    user.isVerified = true;
    user.isActive = true;
    user.otp = null;
    user.otpExpiresAt = null;

    await user.save();

    return res.status(200).json({ message: 'Email verification successful. You can now log in.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error during OTP verification.' });
  }
};
const resendOtp = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.isVerified) return res.status(400).json({ message: 'Email already verified' });

    const otp = generateOTP();
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);

    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    await user.save();

    await sendOtpEmail(email, otp, user.firstname);

    return res.status(200).json({ message: 'OTP resent to your email' });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: 'Server error' });
  }
};

const verifyEmail = async (req, res) => {
  const { token } = req.params;
  if (!token) {
    return res.status(400).json({ error: 'Token is missing' });
  }
  const loginUrl = process.env.FRONTEND_LOGIN_URL
  try {
    const { email } = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(400).json({ error: 'Invalid token or user not found' });
    }

    if (user.isVerified) {
      return res.set("Content-Type", "text/html").send(
        Buffer.from(
          `<div style="text-align:center; font-family: Arial, sans-serif; padding: 20px;">
            <div style="display: inline-block; background-color: #e6f7e6; padding: 20px; border-radius: 10px; border: 2px solid #4CAF50; text-align: center; max-width: 400px;">
              <h2 style="color: #4CAF50; font-size: 24px; font-weight: bold;">
                Your email is already verified.
              </h2>
              <div style="font-size: 40px; color: #4CAF50; margin-bottom: 20px;">&#10004;</div>
              <a href="${loginUrl}" 
                 style="display: inline-block; background-color: #4CAF50; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none; font-weight: bold; font-size: 18px;">
                 Login
              </a>
            </div>
          </div>`
        )
      );
    }

    user.isVerified = true;
    user.isActive = true;
    await user.save();
    return res.set("Content-Type", "text/html").send(
      Buffer.from(
        `<div style="text-align:center; font-family: Arial, sans-serif; padding: 20px;">
          <div style="display: inline-block; background-color: #e6f7e6; padding: 20px; border-radius: 10px; border: 2px solid #4CAF50; text-align: center; max-width: 400px;">
            <h2 style="color: #4CAF50; font-size: 24px; font-weight: bold;">
              Your email is successfully verified. You can log in now.
            </h2>
            <div style="font-size: 40px; color: #4CAF50; margin-bottom: 20px;">&#10004;</div>
            <a href="${loginUrl}" 
               style="display: inline-block; background-color: #4CAF50; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none; font-weight: bold; font-size: 18px;">
               Login
            </a>
          </div>
        </div>`
      )
    );
    
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      const { email } = jwt.decode(token);
      
      return res.set("Content-Type", "text/html").send(
        Buffer.from(
          `<div style="text-align:center; font-family: Arial, sans-serif; padding: 20px;">
            <div style="display: inline-block; background-color: #e6f7e6; padding: 20px; border-radius: 10px; border: 2px solid #FF6347; text-align: center; max-width: 400px;">
              <h2 style="color: #FF6347; font-size: 24px; font-weight: bold;">
                The token has expired. Please request a new verification email.
              </h2>
              <div style="font-size: 40px; color: #FF6347; margin-bottom: 20px;">&#10060;</div>
              <form action="/api/auth/resendVerifyEmail" method="POST">
                <input type="hidden" name="email" value="${email}">
                <button type="submit" style="background-color: #FF6347; color: white; padding: 10px 20px; border-radius: 5px; font-size: 18px;">
                  Resend Verification Email
                </button>
              </form>
            </div>
          </div>`
        )
      );
    }
    
    return res.status(500).json(res, error, 'Verify email error');
  }
};  

const forgetPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  try {
    const user = await User.findOne({ where: { email } });
    //if (!user) return res.status(404).json({ error: 'User not found' });
    if (user) {
      const token = jwtHelper.generateToken(
        { id: user.id },
        `${RESET_TOKEN_TTL_MINUTES}m`
      );

      const expiresAt = new Date(
        Date.now() + RESET_TOKEN_TTL_MINUTES * 60 * 1000
      );

      await PasswordResetToken.create({
        userId: user.id,
        token,
        expiresAt,
        ipAddress: req.ip,
      });

    const url= `${process.env.FORGET_PASSWORD_URL}?token=${token}`;
    await emailHelper.forgotPasswordEmail(user.email, url, user.firstname);
  }
    return res.status(200).json({ message: 'Password reset link sent successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
};

const getResetPassword = async (req, res) => {
  const { token } = req.query; 
  if (!token) {
    return res.status(400).json({ message: 'Token is required to reset password.' });
  }
  try {
    const { email } = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    return res.redirect(`${process.env.RESET_PASSWORD_URL}?token=${token}`);
  } catch (error) {
    return res.status(400).json({ message: 'Invalid or expired token' });
  }
};
const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ message: 'Token and new password are required.' });
  }

  try {
    const decoded = jwtHelper.verifyToken(token);

    const storedToken = await PasswordResetToken.findOne({
      where: { token, userId: decoded.id, used: false, expiresAt: { [Op.gt]: new Date() } },
  });
  if (!storedToken) {
    return res.status(400).json({ message: 'Token is invalid, expired, or has already been used.' });
}

    // if (new Date() > storedToken.expiresAt) {
    //   return res.status(400).json({ message: 'Token expired' });
    // }

    const hashedPassword = await bcryptHelper.hashPassword(newPassword);
    await User.update({ password: hashedPassword }, { where: { id: decoded.id } });

    storedToken.used = true;
    await storedToken.save();

    await Session.destroy({ where: { userId: decoded.id } });

    
    return res.status(200).json({ message: 'Password has been reset successfully. You may now log in.' });

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Password reset token has expired.' });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(400).json({ message: 'Invalid password reset token.' });
    }
    console.error('Reset Password Error:', error);
    return res.status(500).json({ message: 'An internal server error occurred.' });
  }
};
const changePassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ message: 'Old password and new password are required.' });
  }
  try {
    const userId = req.user.id; 
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    const isOldPasswordValid = await bcryptHelper.comparePassword(oldPassword, user.password);
    if (!isOldPasswordValid) {
      return res.status(401).json({ message: 'Old password is incorrect.' });
    }
    const hashedNewPassword = await bcryptHelper.hashPassword(newPassword);
    user.password = hashedNewPassword;
    await user.save();
    return res.status(200).json({ message: 'Password updated successfully.' });
  } catch (error) {
    return res.status(500).json({ message: 'Server error', error });
  }
};
// const logout = async (req, res) => {
//   try {
//     const userId = req.user?.id;
//     res.clearCookie('authToken', {
//       httpOnly: true,
//       secure: true,         
//       sameSite: 'Strict',   
//     });

//     return res.status(200).json({ message: 'Logged out successfully' });
//   } catch (error) {
//     console.error('Logout error:', error);
//     return res.status(500).json({ message: 'Server error during logout' });
//   }
// };
const logout = async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) {
      await Session.destroy({ where: { token } });
    }
    return res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout Error:', error);
    return res.status(500).json({ message: 'Server error during logout' });
  }
};

module.exports = {
  signup,
  login,
  verifyOtp,
  resendOtp,
  logout,
  verifyEmail,
  resendVerificationEmail,
  forgetPassword,
  getResetPassword,
  resetPassword,
  changePassword,
}
