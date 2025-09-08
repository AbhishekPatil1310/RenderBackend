// src/plugins/chat.js
const Message = require("../models/message.model");

const ADMIN_ID = "admin"; // you can replace with real admin _id from DB

module.exports = function (app) {
  const io = app.io;

  io.on("connection", (socket) => {
    app.log.info(`⚡ User connected: ${socket.id}`);

    // User joins their personal room
    socket.on("join", (userId) => {
      socket.join(userId);
      app.log.info(`User ${userId} joined room`);
    });

    // Send message (always to admin)
    socket.on("send_message", async ({ senderId, content }) => {
      if (!content?.trim()) return;

      const message = await Message.create({
        senderId,
        receiverId: ADMIN_ID,
        content,
      });

      // Deliver to admin + sender
      io.to(ADMIN_ID).emit("receive_message", message);
      io.to(senderId).emit("receive_message", message);
    });

    socket.on("disconnect", () => {
      app.log.info(`❌ User disconnected: ${socket.id}`);
    });
  });
};
