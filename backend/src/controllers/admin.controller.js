const { models } = require('mongoose');
const User = require('../models/user.model');
const AD = require('../models/ad.model');
const { sendMail } = require('../utils/mailer');
const AdViewLog = require('../models/AdView.model');
const AffiliateAds = require('../models/AffiliateAds.model');
const Withdrawal = require("../models/withdrawal.model");
const { deleteFromSupabase } = require('../services/supabase.service');

async function getAllUser(req, reply) {
  try {
    const user = await User.find().select('-password');
    return reply.send({ users: user });
  } catch (err) {
    req.log.error(err, '[getAllUser] failed to fetch users')
    return reply.internalServerError('Failed to fetch users');
  }
}

async function getUserBymail(req, reply) {
  const { email } = req.query;

  if (!email) {
    return reply.status(400).send({ message: 'Email query is required' });
  }

  try {
    const users = await User.find({ email: { $regex: email, $options: 'i' } }).select('-password');
    reply.send(users);
  } catch (err) {
    reply.status(500).send({ message: 'Server error' });
  }
}
async function updateUser(req, reply) {
  const { id } = req.params;
  const updates = req.body;

  try {
    const user = await User.findByIdAndUpdate(id, updates, { new: true });
    if (!user) return reply.status(404).send({ message: 'User not found' });
    reply.send(user);
  } catch (err) {
    reply.status(500).send({ message: 'Update failed' });
  }
};

// Delete user
async function deleteUser(req, reply) {
  const { id } = req.params;
  try {
    await User.findByIdAndDelete(id);
    reply.send({ message: 'User deleted' });
  } catch (err) {
    reply.status(500).send({ message: 'Deletion failed' });
  }
};

// Ban user
async function banUser(req, reply) {
  const { id } = req.params;
  const { banFrom, banTo } = req.body; // expecting ISO strings or Date-compatible strings

  if (!banFrom || !banTo) {
    return reply
      .status(400)
      .send({ message: 'banFrom and banTo are required' });
  }

  const banStart = new Date(banFrom);
  const banEnd = new Date(banTo);

  // Validate dates
  if (isNaN(banStart.getTime()) || isNaN(banEnd.getTime())) {
    return reply.status(400).send({ message: 'Invalid date format' });
  }

  if (banEnd <= banStart) {
    return reply.status(400).send({ message: 'banTo must be after banFrom' });
  }

  try {
    const user = await User.findByIdAndUpdate(
      id,
      {
        ban: {
          isBanned: true,
          bannedUntil: banEnd,
        },
      },
      { new: true }
    );

    if (!user) {
      return reply.status(404).send({ message: 'User not found' });
    }

    reply.send({
      message: `User banned from ${banStart.toISOString()} to ${banEnd.toISOString()}`,
      user,
    });
  } catch (err) {
    console.error('Ban error:', err);
    reply.status(500).send({ message: 'Ban failed' });
  }
}

async function unbanUser(req, reply) {
  const { id } = req.params;

  try {
    const user = await User.findByIdAndUpdate(
      id,
      {
        ban: {
          isBanned: false,
          bannedUntil: null,
        },
      },
      { new: true }
    );

    if (!user) {
      return reply.status(404).send({ message: 'User not found' });
    }

    reply.send({ message: 'User unbanned', user });
  } catch (err) {
    console.error('Unban error:', err);
    reply.status(500).send({ message: 'Unban failed' });
  }
}




async function sendMailToUser(req, reply) {
  const { to, subject, message } = req.body;

  if (!to || !subject || !message) {
    return reply.code(400).send({ error: 'Missing fields' });
  }

  try {
    await sendMail({
      to,
      subject,
      html: `<p>${message}</p>`, // You can customize with rich HTML
    });

    reply.send({ success: true, message: 'Mail sent successfully' });
  } catch (err) {
    reply.code(500).send({ error: 'Failed to send mail' });
  }
}
async function addCredit(req, reply) {
  const { userId, amount } = req.body;
  if (!userId || !amount) {
    return reply.status(400).send({ message: 'User ID and amount are required' });
  }
  try {
    const user = await User.findById(userId)
    if (!user || user.role !== 'advertiser') {
      return reply.notFound('Advertiser not found');
    }
    user.credit += amount;
    await user.save();
    reply.send({ success: true, message: 'Credit added successfully', credit: user.credit });
  } catch (err) {
    console.error('Error adding credit:', err);
    reply.internalServerError('Failed to add credit');
  }

}

async function getAllAdsAnalytics(req, reply) {
  try {
    // Fetch all ads with _id, description, feedbacks
    const ads = await AD.find().select('_id description feedbacks');

    const adIds = ads.map(ad => ad._id);

    // 1. Views over time (grouped by date)
    const viewsOverTime = await AdViewLog.aggregate([
      { $match: { adId: { $in: adIds } } },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$viewedAt' } },
          },
          count: { $sum: 1 },
        },
      },
      { $sort: { '_id.date': 1 } },
    ]);

    // 2. Most viewed ads
    const mostViewedRaw = await AdViewLog.aggregate([
      { $match: { adId: { $in: adIds } } },
      {
        $group: {
          _id: '$adId',
          count: { $sum: 1 },
        },
      },
      { $sort: { count: -1 } },
      { $limit: 5 },
    ]);

    // Map adId to description for lookup
    const adTitleMap = {};
    ads.forEach(ad => {
      adTitleMap[ad._id.toString()] = ad.description;
    });

    const mostViewed = mostViewedRaw.map(view => ({
      title: adTitleMap[view._id.toString()] || 'Unknown',
      count: view.count,
    }));

    // 3. Feedbacks (like/dislike) from embedded arrays
    const feedbackCounts = ads.map(ad => {
      const feedbacks = ad.feedbacks || [];
      const like = feedbacks.filter(f => f.sentiment === 'like').length;
      const dislike = feedbacks.filter(f => f.sentiment === 'dislike').length;
      return {
        title: ad.description,
        like,
        dislike,
      };
    });

    const mostLiked = [...feedbackCounts]
      .sort((a, b) => b.like - a.like)
      .slice(0, 5)
      .map(f => ({ title: f.title, count: f.like }));

    const mostDisliked = [...feedbackCounts]
      .sort((a, b) => b.dislike - a.dislike)
      .slice(0, 5)
      .map(f => ({ title: f.title, count: f.dislike }));

    // Send analytics
    reply.send({
      viewsOverTime,
      mostViewed,
      mostLiked,
      mostDisliked,
    });
  } catch (err) {
    req.log.error(err);
    reply.internalServerError('Failed to load admin analytics');
  }
}

async function getAds(req, reply) {
  try {
    const { id } = req.params;
    console.log('Fetching ads for advertiser ID:', id);

    if (!id) {
      return reply.badRequest('Missing advertiser ID');
    }

    const ads = await AD.find({ advertiserId: id })
      .populate('advertiserId', 'name email');

    return reply.send({ ads });
  } catch (err) {
    req.log.error(err, '[getAds] failed to fetch ads');
    return reply.internalServerError('Failed to fetch ads');
  }
}


// Delete an ad by ID
async function deleteAd(req, reply) {
  try {
    const { id } = req.params;
    console.log('[deleteAd] Deleting ad with ID:', id);

    if (!id) {
      return reply.badRequest('Missing ad ID');
    }

    const ad = await AD.findById(id);
    if (!ad) {
      return reply.notFound('Ad not found');
    }

    // Get file path from Supabase public URL
    const imageUrl = ad.imageUrl;
    const publicPrefix = `${process.env.SUPABASE_URL}/storage/v1/object/public/${process.env.SUPABASE_BUCKET}/`;
    const filePath = imageUrl.replace(publicPrefix, '');

    // Delete the image from Supabase
    try {
      await deleteFromSupabase(filePath);
      console.log('[deleteAd] Image deleted from Supabase ✅');
    } catch (imageErr) {
      console.warn('[deleteAd] Supabase image deletion failed ❌', imageErr.message);
      // Optional: don't fail the whole process if image deletion fails
    }

    // Delete the ad from MongoDB
    await AD.findByIdAndDelete(id);

    return reply.send({ success: true, message: 'Ad and image deleted successfully' });
  } catch (err) {
    req.log.error(err, '[deleteAd] Failed to delete ad');
    return reply.internalServerError('Failed to delete ad');
  }
}

async function getAffilateAds(req, reply) {
  const ads = await AffiliateAds.find().sort({ createdAt: -1 });
  reply.send(ads);
}

async function AddAffiliateAd(req, reply) {
  const { name, discrption, price, ImageUrl, AffiliateLink } = req.body;
  const ad = new AffiliateAds({ name, discrption, price, ImageUrl, AffiliateLink });
  await ad.save();
  reply.send({ success: true, ad });
};

async function updateAffiliateAd(req, reply) {
  const { id } = req.params;
  const updates = req.body;
  const ad = await AffiliateAds.findByIdAndUpdate(id, updates, { new: true });
  if (!ad) return reply.notFound('Ad not Found');
  reply.send({ success: true, ad });
};

async function DeleteAffiliateAd(req, reply) {
  const { id } = req.params;
  const deleteAd = await AffiliateAds.findByIdAndDelete(id);
  if (!deleteAd)
    return reply.notFound('Ad not found');
  reply.send({ success: true, message: 'Ad deleted successfully!' })
};


async function getWithdrawals(req, reply) {
  try {
    const withdrawals = await Withdrawal.find().sort({ createdAt: -1 });
    return reply.send({ success: true, withdrawals });
  } catch (err) {
    req.log.error(err);
    return reply.status(500).send({ error: "Server error" });
  }
}




async function updateWithdrawalStatus(req, reply) {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!["approved", "rejected"].includes(status)) {
      return reply.status(400).send({ error: "Invalid status value" });
    }

    const withdrawal = await Withdrawal.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );
    console.log("the id is ☠️🕺🕺🕺🕺🕺🕺🕺🕺🕺🕺🕺🕺🕺🕺🕺:",id)

    if (!withdrawal) {
      return reply.status(404).send({ error: "Withdrawal not found" });
    }

    return reply.send({
      success: true,
      msg: `Withdrawal status updated to ${status}`,
      withdrawal,
    });
  } catch (err) {
    req.log.error(err);
    return reply.status(500).send({ error: "Server error" });
  }
}

// Bulk update all withdrawals
async function bulkUpdateWithdrawalStatus(req, reply) {
  try {
    const { status } = req.body;

    if (!["approved", "rejected"].includes(status)) {
      return reply.status(400).send({ error: "Invalid status value" });
    }

    await Withdrawal.updateMany({}, { status });

    return reply.send({
      success: true,
      msg: `All withdrawals updated to ${status}`,
    });
  } catch (err) {
    req.log.error(err);
    return reply.status(500).send({ error: "Server error" });
  }
}



module.exports = {
  getAllUser, getUserBymail, updateUser, deleteUser, banUser, unbanUser, sendMailToUser, addCredit,
  getAllAdsAnalytics, getAds, deleteAd, getAffilateAds, AddAffiliateAd, updateAffiliateAd, DeleteAffiliateAd, getWithdrawals,updateWithdrawalStatus,bulkUpdateWithdrawalStatus
};