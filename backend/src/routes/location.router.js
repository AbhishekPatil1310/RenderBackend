const {updateUserLocation} = require('../controllers/location.controller');

async function locationRouter(fastify) {
  fastify.put('/location', {
    preHandler: [fastify.authenticate],  // ⬅️ This is necessary
  }, updateUserLocation);
}

module.exports = locationRouter;