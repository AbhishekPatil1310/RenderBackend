const User = require('../models/user.model');
const Token = require('../models/token.model');
const {
  generateRefreshToken,
  revokeRefreshToken,
  seconds,
} = require('../utils/token.util');
const env = require('../config/env');

const { sendOtpEmail, verifyStoredOtp } = require('../utils/otp.util');
/**
 * Helper: sets HTTP‑only auth cookies.
 */
function setAuthCookies(reply, accessToken, refreshToken) {
  const isProd = env.NODE_ENV === 'production';
  const accessMaxAge = seconds(env.JWT_ACCESS_EXPIRES_IN);
  const refreshMaxAge = seconds(env.JWT_REFRESH_EXPIRES_IN);

  reply
    .setCookie('accessToken', accessToken, {
      httpOnly: true,
      sameSite: isProd ? 'none' : 'lax',
      secure: isProd,
      path: '/',
      maxAge: accessMaxAge,
    })
    .setCookie('refreshToken', refreshToken, {
      httpOnly: true,
      sameSite: isProd ? 'none' : 'lax',
      secure: isProd,
      path: '/', // ✅ corrected path
      maxAge: refreshMaxAge,
    });
}


function clearAuthCookies(reply) {
  const isProd = env.NODE_ENV === 'production';
  reply
    .clearCookie('accessToken', {
      httpOnly: true,
      sameSite: isProd ? 'none' : 'lax',
      secure: isProd,
      path: '/',
    })
    .clearCookie('refreshToken', {
      httpOnly: true,
      sameSite: isProd ? 'none' : 'lax',
      secure: isProd,
      path: '/',
    });
}

/* ───────────────── register ───────────────── */
module.exports.register = async function register(request, reply) {
  try {
    const {
      name,
      email,
      password,
      role = 'user',
      companyName,
      mobileNumber,
    } = request.body;

    const existing = await User.findOne({ email });
    if (existing) return reply.badRequest('Email already registered');

    if (!['user', 'advertiser', 'admin'].includes(role))
      return reply.badRequest('Invalid role');

    const userData = { name, email, password, role };

    // Add advertiser-specific fields if applicable
    if (role === 'advertiser') {
      if (!companyName || !mobileNumber) {
        return reply.badRequest('Company name and mobile number required');
      }

      userData.companyName = companyName;
      userData.mobileNumber = mobileNumber;
    }

    // ✅ Create user
    const user = await User.create(userData);

    // ✅ Send OTP Email (OTP is hashed and stored inside sendOtpEmail)
    await sendOtpEmail(user.email);

    // ✅ Send minimal response (NO TOKENS yet)
    reply.code(201).send({
      message: 'Registered successfully. OTP sent to email.',
      email: user.email,
    });
  } catch (err) {
    request.log.error(err);
    reply.internalServerError();
  }
};

/* ───────────────── login ───────────────── */
module.exports.login = async function login(request, reply) {
  try {
    const { email, password } = request.body;

    const user = await User.findOne({ email }).select('+password');
    if (!user) return reply.unauthorized('Invalid credentials');

    const isMatch = await user.isPasswordMatch(password);
    if (!isMatch) return reply.unauthorized('Invalid credentials');

    const accessToken = await reply.jwtSign({ sub: user._id, role: user.role });
    const refreshToken = await generateRefreshToken(user._id, reply);

    setAuthCookies(reply, accessToken, refreshToken);

    reply.send({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        ban: user.ban || null, // <-- include ban info
      },
    });
  } catch (err) {
    request.log.error(err);
    reply.internalServerError();
  }
};

/* ───────────────── refresh ───────────────── */
// src/controllers/auth.controller.js
module.exports.refresh = async function refresh(request, reply) {
  try {
    // 1️⃣  read the token from body OR cookie
    const refreshToken =
      request.body?.refreshToken || request.cookies.refreshToken;
    if (!refreshToken) return reply.badRequest('Refresh token required');

    // 2️⃣  verify *explicit* token string
    let decoded;
    try {
      //  ✨  `this` inside a Fastify handler === fastify instance
      decoded = await this.jwt.verify(refreshToken);
      //            ↑↑              ↑↑
      //            fastify.jwt.verify(token)
    } catch {
      return reply.unauthorized('Invalid refresh token');
    }

    // 3️⃣  confirm the token is still in DB
    const tokenHash = Token.createHashedToken(refreshToken);
    const stored = await Token.findOne({ tokenHash, user: decoded.sub });
    if (!stored) return reply.unauthorized('Refresh token revoked');

    // 4️⃣  issue new access token, reuse refresh token
    const accessToken = await reply.jwtSign({
      sub: decoded.sub,
      role: decoded.role,
    });
    setAuthCookies(reply, accessToken, refreshToken);

    return reply.send({ accessToken });
  } catch (err) {
    request.log.error(err);
    reply.internalServerError();
  }
};

/* ───────────────── logout ───────────────── */
module.exports.logout = async function logout(request, reply) {
  try {
    const refreshToken =
      request.body?.refreshToken || request.cookies.refreshToken;
    if (refreshToken) await revokeRefreshToken(refreshToken);

    clearAuthCookies(reply);

    reply.send({ message: 'Logged out' });
  } catch (err) {
    request.log.error(err);
    reply.internalServerError();
  }
};

module.exports.getCurrentUser = async function (request, reply) {
  try {
    reply.send({ user: request.userData });
  } catch (err) {
    request.log.error(err);
    reply.internalServerError();
  }
};

module.exports.verifyOtp = async function verifyOtp(request, reply) {
  const { email, otp } = request.body;

  const user = await User.findOne({ email });
  if (!user) return reply.notFound('User not found');

  const isValid = await verifyStoredOtp(email, otp);
  if (!isValid) return reply.badRequest('Invalid or expired OTP');

  // ✅ OTP verified – now issue tokens
  const accessToken = await reply.jwtSign({ sub: user._id, role: user.role });
  const refreshToken = await generateRefreshToken(user._id, reply);
  setAuthCookies(reply, accessToken, refreshToken);

  reply.send({
    message: 'Email verified. Logged in.',
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      companyName: user.companyName,
      mobileNumber: user.mobileNumber,
    },
  });
};

module.exports.resendOtp = async function (request, reply) {
  const { email } = request.body;
  const user = await User.findOne({ email });
  if (!user) return reply.notFound('User not found');
  if (user.isEmailVerified) return reply.badRequest('Email already verified');
  await sendOtpEmail(email);
  reply.send({ message: 'OTP resent successfully', expiresAt });
};

module.exports.getOtpExpiry = async function getOtpExpiry(req, reply) {
  const { email } = req.query;

  if (!email) {
    return reply.badRequest('Email is required');
  }

  const user = await User.findOne({ email });
  if (!user) return reply.notFound('User not found');

  if (!user.otpExpires) {
    return reply.badRequest('No OTP expiry set for this user');
  }

  reply.send({
    expiresAt: user.otpExpires.toISOString(),
  });
};

// 1️⃣ Send OTP
module.exports.forgotPassword = async function forgotPassword(request, reply) {
  try {
    const { email } = request.body;
    const user = await User.findOne({ email });

    if (!user) return reply.status(404).send({ message: "User not found" });

    const otp = crypto.randomInt(100000, 999999).toString();

    // hash OTP before saving
    const salt = await bcrypt.genSalt(10);
    const hashedOtp = await bcrypt.hash(otp, salt);

    user.passreOTP = hashedOtp;
    user.passreOTPExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
    await user.save();

    await sendMail({
      to: email,
      subject: "Password Reset OTP",
      html: `<h3>Your OTP is: <b>${otp}</b></h3><p>It will expire in 5 minutes.</p>`,
    });

    return reply.send({ message: "OTP sent to email" });
  } catch (err) {
    request.log.error(err);
    return reply.internalServerError("Something went wrong");
  }
},

  // 2️⃣ Verify OTP
  module.exports.FverifyOtp = async function FverifyOtp(request, reply) {
    try {
      const { email, otp } = request.body;
      const user = await User.findOne({ email }).select("passreOTP passreOTPExpires");
      console.log("user is: ",user.passreOTP)

      if (!user || !user.passreOTP) {
        return reply.status(400).send({ message: "OTP not found" });
      }

      if (user.passreOTPExpires < Date.now()) {
        return reply.status(400).send({ message: "OTP expired" });
      }

      const isMatch = await bcrypt.compare(otp, user.passreOTP);
      if (!isMatch) {
        return reply.status(400).send({ message: "Invalid OTP" });
      }

      return reply.send({ message: "OTP verified successfully" });
    } catch (err) {
      request.log.error(err);
      return reply.internalServerError("Something went wrong");
    }
  },

module.exports.resetPassword = async function resetPassword(request, reply) {
  try {
    const { email, newPassword } = request.body;
    const user = await User.findOne({ email }).select("passreOTP passreOTPExpires");

    if (!user) {
      return reply.status(404).send({ message: "User not found" });
    }

    if (!user.passreOTP || user.passreOTPExpires < Date.now()) {
      return reply.status(400).send({ message: "OTP expired or not verified" });
    }

    user.password = newPassword;

    // clear OTP fields
    user.passreOTP = undefined;
    user.passreOTPExpires = undefined;

    await user.save();

    return reply.send({ message: "Password reset successfully" });
  } catch (err) {
    request.log.error(err);
    return reply.internalServerError("Something went wrong");
  }
};
