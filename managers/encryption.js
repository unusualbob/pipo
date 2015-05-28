var crypto = require('crypto');
var kbpgp = require('kbpgp');

function EncryptionManager() {
  var calculatedKeys = {};
  var keyRing = new kbpgp.keyring.KeyRing();

  this.getKeyFingerprint = function (key, callback) {
    var self = this;
    var fingerprint;

    //Perform a sha1 hash of the key to create a unique short string for storage
    var keyHash = crypto.createHash('sha1').update(key).digest('hex');

    //Check to see if we've already fingerprinted this key and return it so we don't have to check a lot
    if (self.calculatedKeys[keyHash]) {
      return callback(null, self.calculatedKeys[keyHash].fingerprint);
    }

    kbpgp.KeyManager.import_from_armored_pgp({
      armored: key
    }, function(err, keyManager) {
      if (err) {
        return callback(err);
      }
      if (!keyManager) {
        return callback(new Error("Key could not be loaded"));
      }

      fingerprint = keyManager.get_pgp_fingerprint_str();

      //Store fingerprint for later usage
      self.calculatedKeys[keyHash] = {
        fingerprint: fingerprint,
        instance: keyManager
      };

      //Add to our keyRing
      keyRing.add_key_manager(keyManager);

      return callback(null, fingerprint);
    });
  };

  this.verifyMessageSignature = function(signedMessage, publicKey, callback) {
    var signer, keyManager, signatureFingerprint;

    this.getKeyFingerprint(publicKey, function(err, publicKeyFingerprint) {
      if (err) {
        return callback(err);
      }

      kbpgp.unbox({keyfetch: keyRing, armored: signedMessage}, function(err, literals) {
        if (err) {
          return callback(err);
        }
        signer = literals[0].get_data_signer();

        if (!signer) {
          return callback(new Error("Message was not signed, no signer found"));
        }

        keyManager = signer.get_key_manager();

        if (!keyManager) {
          return callback(new Error("Message was not signed, no keyManager instance"));
        }

        signatureFingerprint = keyManager.get_pgp_fingerprint_str();

        if (signatureFingerprint !== publicKeyFingerprint) {
          return callback(new Error("Signature does not match provided publicKey"));
        }

        return callback(null, signatureFingerprint);
      });
    });
  };
}

module.exports = new EncryptionManager();
