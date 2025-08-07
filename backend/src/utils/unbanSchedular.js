const cron = require('node-cron');
const User = require('../models/user.model');

// Run every minute to check for expired bans
cron.schedule('* * * * *', async () => {
  try {
    const now = new Date();
    const unbannedUsers = await User.updateMany(
      {
        'ban.isBanned': true,
        'ban.bannedUntil': { $lte: now },
      },
      {
        $set: {
          'ban.isBanned': false,
          'ban.bannedUntil': null,
        },
      }
    );

    if (unbannedUsers.modifiedCount > 0) {
      console.log(`Unbanned ${unbannedUsers.modifiedCount} users`);
    }
  } catch (err) {
    console.error('Error unbanning users:', err);
  }
});