const { getAllUser, getUserBymail, updateUser, deleteUser, banUser, unbanUser, sendMailToUser, addCredit, getAllAdsAnalytics, getAds, deleteAd, getAffilateAds, AddAffiliateAd, updateAffiliateAd, DeleteAffiliateAd } = require('../controllers/admin.controller');
const fp = require('fastify-plugin');
async function adminRoutes(fastify) {
    fastify.get('/admin/users', getAllUser);
    fastify.get('/admin/users/search', getUserBymail);
    fastify.put('/admin/users/:id', updateUser);
    fastify.put('/admin/users/:id/ban', banUser);
    fastify.delete('/admin/users/:id', deleteUser);
    fastify.delete('/admin/ads/:id', deleteAd);
    fastify.post('/admin/mail', sendMailToUser);
    fastify.post('/admin/credit', addCredit);
    fastify.get('/admin/ads/analytics', getAllAdsAnalytics);
    fastify.get('/admin/ads/:id', getAds);
    fastify.get('/getAffiliateAds', getAffilateAds);
    fastify.post('/addAffiliateAd', AddAffiliateAd);
    fastify.put('/updateAffiliateAd/:id', updateAffiliateAd);
    fastify.delete('/deleteAffiliateAd/:id', DeleteAffiliateAd);
    fastify.put('/admin/users/:id/unban', unbanUser);
}

module.exports = fp(adminRoutes);