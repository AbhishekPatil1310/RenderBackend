const Razorpay = require("razorpay");
const env = require("../config/env");

const razorpayI = new Razorpay({
  key_id: env.RAZORPAY_KEY_ID,
  key_secret: env.RAZORPAY_KEY_SECRET,
});

async function paymentRoutes(fastify) {
  console.log("trigred pay✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️✔️")
  fastify.post("/create-order", async (req, reply) => {
    const options = {
      amount: 100000, // in paise (₹100)
      currency: "INR",
      receipt: "txn_12345",
    };

    try {
      const order = await razorpayI.orders.create(options);
      reply.send(order);
    } catch (err) {
      reply.status(500).send({ error: err.message });
    }
  });
}

module.exports = paymentRoutes;
