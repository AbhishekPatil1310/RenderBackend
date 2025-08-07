const { sendMail } = require('./mailer');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const User = require('../models/user.model');
const env = require('../config/env');

// Generate 6-digit numeric OTP
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOtpEmail(email) {
  const otp = generateOtp();
  const hashedOtp = await bcrypt.hash(otp, 10);
  const expiresAt = new Date(Date.now() + env.OTP_EXPIRE_MINUTES * 60 * 1000); // 5 minutes

  // Update user with hashed OTP and expiry
  await User.findOneAndUpdate(
    { email },
    { emailOTP: hashedOtp, otpExpires: expiresAt }
  );

  const html = `
    <p>Dear User,</p>

<p>Thank you for registering with our platform. To complete your email verification, please use the OTP provided below:</p>

<p>Your OTP is <strong>${otp}</strong></p>

<p>This OTP is valid for <strong>5 minutes</strong>. Please do not share this code with anyone for security reasons.</p>

<p>If you did not initiate this request, please ignore this email.</p>

<p>Best regards,<br />
The AdVision Team</p>

  `;

  await sendMail({
    to: email,
    subject: 'Your OTP for Email Verification',
    html,
  });
}

async function verifyStoredOtp(email, otp) {
  const user = await User.findOne({ email });
  if (!user || !user.emailOTP || !user.otpExpires) return false;

  const notExpired = user.otpExpires > new Date();
  const isMatch = await bcrypt.compare(otp, user.emailOTP);

  if (isMatch && notExpired) {
    // Clear OTP fields after success
    user.emailOTP = undefined;
    user.otpExpires = undefined;
    user.isEmailVerified = true;
    await user.save();
    return true;
  }

  return false;
}

module.exports = { sendOtpEmail, verifyStoredOtp };
