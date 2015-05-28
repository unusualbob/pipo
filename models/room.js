var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var ObjectId = mongoose.SchemaTypes.ObjectId;
var EncryptionManager = require('../managers/encryption');
var Room;

var member = new Schema({
  _user: { type: ObjectId, ref: "User", required: true },
  fingerprint: { type: String, required: true },
  signatures: [{
    _signingUser: { type: ObjectId, ref: "User", required: true },
    signedMessage: { type: String, required: true },
    invite: Boolean
  }]
});

var roomSchema = new Schema({
  name: { type: String, required: true, unique: true, minlength: 3, maxlength: 80 },
  members: [member],
  prospectiveMembers: [member],
  restrictions: {
    inviteOnly: { type: Boolean, default: true },
    signaturesRequired: { type: Number, default: 2 }
  }
});

roomSchema.statics.create = function createRoom(roomName, creatorUser, callback) {

  EncryptionManager.getKeyFingerprint(creatorUser.publicKey, function(err, fingerprint) {
    if (err) {
      return callback(err);
    }

    new Room({
      name: roomName,
      members: [{
        _user: creatorUser._id,
        fingerprint: fingerprint,
        permissions: ['owner'],
      }]
    }).save(callback);
  });
};

roomSchema.methods.inviteUser = function inviteUser(requestingUser, invitedUser, signedInvite, callback) {
  var self = this;

  self.findMember(requestingUser._id, function(err, member) {
    if (err) {
      return callback(err);
    }
    self.findMember(invitedUser._id, function(err, member) {
      if (member) {
        return callback(new Error("User is already a member of this room"));
      }

      EncryptionManager.verifyMessageSignature(signedInvite, requestingUser.publicKey, function(err) {
        if (err) {
          return callback(err);
        }

        EncryptionManager.getKeyFingerprint(invitedUser.publicKey, function(err, fingerprint) {
          if (err) {
            return callback(err);
          }

          self.$addToSet({
            _user: invitedUser._id,
            fingerprint: fingerprint,
            signatures: [{
                _signingUser: requestingUser._id,
                signedMessage: signedInvite,
                invite: true
            }]
          });

          self.save(callback);
        });
      });
    });
  });
};

roomSchema.methods.findMember = function findMember(userId, callback) {
  var member;
  var memberIndex = -1;
  var errorMessage = "User is not a member of this room";

  if (!this.members || !this.members.length) {
    return callback(new Error(errorMessage));
  }

  member = this.members.some(function(member, i) {
    memberIndex = i;
    return member._user.toString() == userId.toString;
  });

  if (!member) {
    return callback(new Error(errorMessage));
  }

  return callback(null, this.members[memberIndex]);
};

module.exports = Room = mongoose.model('Room', roomSchema);