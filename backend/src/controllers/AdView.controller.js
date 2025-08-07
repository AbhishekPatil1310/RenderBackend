// controllers/adView.controller.js
const Ad = require('../models/ad.model');
const AdViewLog = require('../models/AdView.model');

const User = require('../models/user.model');

async function logAdView(req, reply) {
  const { adId } = req.body;
  const userId = req.user?.sub || null;
  const ip = req.ip;

  console.log('Logging view:', { adId, userId, ip });

  // Check recent view
  let recentView;

  if (userId) {
    // Logged-in users: only check if the same user has seen it in last 24h
    recentView = await AdViewLog.findOne({
      adId,
      userId,
      viewedAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) },
    });
  } else {
    // Guest users: check by IP only
    recentView = await AdViewLog.findOne({
      adId,
      ip,
      viewedAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) },
    });
  }

  if (recentView) {
    return reply.send({ counted: false, message: 'Already viewed recently' });
  }

  // Create the view log
  const view = await AdViewLog.create({ adId, userId, ip });
  await Ad.findByIdAndUpdate(adId, { $inc: { views: 1 } });

  // Add credit to logged-in user
  if (userId) {
    await User.findByIdAndUpdate(userId, { $inc: { credit: 0.3 } });
  }

  return reply.send({ counted: true, message: 'View recorded' });
}



module.exports = { logAdView };
