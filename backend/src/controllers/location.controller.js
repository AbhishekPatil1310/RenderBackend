const User = require('../models/user.model');

exports.updateUserLocation = async (request, reply) => {
  const {
    Latitude,
    Longitude,
    fullAddress,
    road,
    city,
    state,
    postcode,
    country,
  } = request.body;

  try {
    // Fastify stores request user metadata in request.user
    const userId = request.user?.sub;

    const user = await User.findById(userId);

    if (!user) {
      return reply.code(404).send({ message: 'User not found.' });
    }

    user.Useraddress = {
      Latitude,
      Longitude,
      fullAddress,
      road,
      city,
      state,
      postcode,
      country,
    };

    user.locationEnabled = true;
    user.lastLocationUpdate = new Date();

    await user.save();

    return reply.code(200).send({
      message: 'Location updated.',
      locationEnabled: true,
    });
  } catch (err) {
    console.error('Location update failed:', err);
    return reply.code(500).send({ message: 'Failed to update location.' });
  }
};
