const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: function() {
      return !this.googleId;  // Only required if not a Google user
    }
  },
  resetPasswordToken: {
    type: String
  },
  resetPasswordExpires: {
    type: Date
  },
  googleId: {
    type: String
  },
  twoFactorSecret: {
    type: String
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  authMethod: {
    type: String,
    enum: ['local', 'google'],
    required: true
  },
  date: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('User', UserSchema);