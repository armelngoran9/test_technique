const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    email: { type: String, unique: true },
    mdp: { type: String },
});

module.exports = mongoose.model("user", userSchema);