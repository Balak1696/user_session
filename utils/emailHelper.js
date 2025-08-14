const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
dotenv.config();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.APP_EMAIL,
        pass: process.env.APP_PASSWORD,
    }
});
const sendOtpEmail = async (to, otp, username) => {
    await transporter.sendMail({
      from: process.env.APP_EMAIL,
      to,
      subject: 'Your OTP for email verification',
      html: `
        <div style="padding: 20px; font-family: Arial;">
          <h2>Email Verification OTP</h2>
          <p>Hi ${username},</p>
          <p>Your OTP for verifying your email is: <strong>${otp}</strong></p>
          <p>This OTP is valid for 5 minutes.</p>
        </div>
      `
    });
  };
  
const verificationEmail = async(to, url, username)=>{
    await transporter.sendMail({
        from: process.env.APP_EMAIL,
        to,
        subject:'E-mail verification',
        html:`<div style="width: 950px; height: 230px; background-color: white; border: 1px solid black; padding: 20px; text-align: left;">
        <h2 style="text-align: center; margin-bottom: 20px;">VERIFY E-MAIL</h2>
        <p style="font-size: 16px; color: #333; text-align: left; margin-bottom: 20px;">Hi ${username},</p>
        <p style="font-size: 16px; color: #333; text-align: left; margin-bottom: 20px;">Here's your email verification link. You can click below to verify your email</p>
        <p style="text-align: left; margin-bottom: 0;"><a href="${url}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
        <p style="font-size: 16px; color: #333; text-align: left; margin-bottom: 20px;">If not you kindly ingnore this mail</p>

    </div>`
    })
}

const forgotPasswordEmail = async(to, url, username)=>{
    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to,
        subject:'Reset Password',
        html:`<div style="width: 950px; height: 230px; background-color: white; border: 1px solid black; padding: 20px; text-align: left;">
        <h2 style="text-align: center; margin-bottom: 20px;">RESET PASSWORD</h2>
        <p style="font-size: 16px; color: #333; text-align: left; margin-bottom: 20px;">Hi ${username},</p>
        <p style="font-size: 16px; color: #333; text-align: left; margin-bottom: 20px;">Here's your password reset link. You can click below to reset your password</p>
        <p style="text-align: left; margin-bottom: 0;"><a href="${url}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
        <p style="font-size: 16px; color: #333; text-align: left; margin-bottom: 20px;">If not you kindly ingnore this mail</p>

    </div>`
   
    })
    console.log(url)
}
const sendOrderConfirmationEmail = async (to, username, products, address, city, pincode, invoicePath) => {
  let rows = '';
  let total = 0;

  products.forEach(product => {
      const subtotal = product.qty * product.price;
      total += subtotal;
      rows += `
          <tr>
              <td style="border: 1px solid #ddd; padding: 8px;">${product.name}</td>
              <td style="border: 1px solid #ddd; padding: 8px;">${product.qty}</td>
              <td style="border: 1px solid #ddd; padding: 8px;">Rs ${product.price.toFixed(2)}</td>
              <td style="border: 1px solid #ddd; padding: 8px;">Rs ${subtotal.toFixed(2)}</td>
          </tr>
      `;
  });

  const htmlContent = `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
          <p>Dear ${username},</p>
          <p>Thank you for your order!</p>
          <h3>Order Details</h3>
          <table style="border-collapse: collapse; width: 100%;">
              <thead>
                  <tr>
                      <th style="border: 1px solid #ddd; padding: 8px;">Product</th>
                      <th style="border: 1px solid #ddd; padding: 8px;">Qty</th>
                      <th style="border: 1px solid #ddd; padding: 8px;">Price</th>
                      <th style="border: 1px solid #ddd; padding: 8px;">Subtotal</th>
                  </tr>
              </thead>
              <tbody>
                  ${rows}
                  <tr>
                      <td colspan="3" style="border: 1px solid #ddd; padding: 8px; text-align:right;"><strong>Total</strong></td>
                      <td style="border: 1px solid #ddd; padding: 8px;"><strong>Rs ${total.toFixed(2)}</strong></td>
                  </tr>
              </tbody>
          </table>
          <h3>Shipping Address</h3>
          <p>${address},<br>${city}, ${pincode}</p>
          <p>We will contact you soon.</p>
      </div>
  `;

  const attachments = [];
  if (invoicePath && fs.existsSync(invoicePath)) {
      attachments.push({
          filename: path.basename(invoicePath),
          path: invoicePath,
          contentType: 'application/pdf'
      });
  }

  await transporter.sendMail({
      from: process.env.APP_EMAIL,
      to,
      subject: 'Order Confirmation & Invoice',
      html: htmlContent,
      attachments
  });
};


module.exports = { 
    verificationEmail,
    forgotPasswordEmail,
    sendOtpEmail,
    sendOrderConfirmationEmail
}