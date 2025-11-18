const fp = require('fastify-plugin');
const { setAgeHandler } = require('../controllers/user.controller');
const authController = require('../controllers/auth.controller');
const oauthController = require('../controllers/oauth.controller');

async function authRoutes(fastify) {
  fastify.post('/auth/register', {
    schema: {
      body: {
        type: 'object',
        required: ['name', 'email', 'password'],
        additionalProperties: false,
        properties: {
          name: { type: 'string' },
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 6 },
          role: { type: 'string', enum: ['user', 'advertiser', 'admin'] },
          companyName: { type: 'string' },
          mobileNumber: { type: 'string' },
        },
      },
    },
    handler: authController.register,
  });

    fastify.post('/auth/register/Ad', {
    schema: {
      body: {
        type: 'object',
        required: ['name', 'email', 'password'],
        additionalProperties: false,
        properties: {
          name: { type: 'string' },
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 6 },
          role: { type: 'string', enum: ['user', 'advertiser', 'admin'] },
          companyName: { type: 'string' },
          mobileNumber: { type: 'string' },
        },
      },
    },
    handler: authController.register,
  });

  fastify.post('/auth/login', {
    schema: {
      body: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string' },
        },
      },
    },
    handler: authController.login,
  });

    fastify.post('/auth/login/Ad', {
    schema: {
      body: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string' },
        },
      },
    },
    handler: authController.login,
  });
  // ── OTP Verify ──────────────────────
  fastify.post('/auth/verify-otp', {
    schema: {
      body: {
        type: 'object',
        required: ['email', 'otp'],
        additionalProperties: false,
        properties: {
          email: { type: 'string', format: 'email' },
          otp: { type: 'string', minLength: 6, maxLength: 6 },
        },
      },
    },
    handler: authController.verifyOtp,
  });

  // ── Resend OTP ──────────────────────
  fastify.post('/auth/resend-otp', {
    schema: {
      body: {
        type: 'object',
        required: ['email'],
        additionalProperties: false,
        properties: {
          email: { type: 'string', format: 'email' },
        },
      },
    },
    handler: authController.resendOtp,
  });

  fastify.get('/auth/get-otp-expiry', authController.getOtpExpiry);


  fastify.put('/auth/set-age', {
    preHandler: [fastify.authenticate],
    handler: setAgeHandler,
  });

  fastify.post('/auth/refresh', authController.refresh);

  fastify.post('/auth/logout', authController.logout);

  fastify.get(
    '/auth/me',
    { preHandler: [fastify.authenticate] },
    authController.getCurrentUser
  );

  // Google OAuth routes
  fastify.get('/auth/google', oauthController.googleOAuth);

  fastify.get('/auth/google/callback', oauthController.googleCallback);
   fastify.post('/forgot-password', authController.forgotPassword);
  fastify.post('/Fverify-otp', authController.FverifyOtp);
  fastify.post('/reset-password', authController.resetPassword);
}

module.exports = fp(authRoutes);


