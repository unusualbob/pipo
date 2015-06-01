var User = require('./models/user');
var KeyId = require('./models/keyid');
var KeyPair = require('./models/keypair');

var config = ({
  encryptionScheme: 'masterKey'
});

/**
 * Handles all socket traffic
 * @param namespace
 * @returns {Function}
 * @constructor
 */
function SocketServer(namespace) {
  this.namespace = namespace;
  if (!this.namespace.socketMap) {
    this.namespace.socketMap = {};
  }
  if (!this.namespace.userMap) {
    this.namespace.userMap = {};
  }
}

SocketServer.prototype.onSocket = function(socket) {
  var self = this;
  this.socket = socket;

  console.log("[CONNECTION] Socket connected to main");

  socket.on('authenticate', self.authenticate.bind(self));

  socket.on('updateClientKey', self.updateClientKey.bind(self));
  socket.on('disconnect', self.disconnect.bind(self));

  socket.on('join', self.joinChannel.bind(self));
  socket.on('part', self.leaveChannel.bind(self));

  socket.on('roomMessage', self.onMessage.bind(self));
  socket.on('privateMessage', self.onPrivateMessage.bind(self));

  socket.on('serverCommand', self.onServerCommand.bind(self));

  /**
   * ADMIN COMMANDS
   */
  // TODO Put this behind admin control when new client keys are approved
  socket.on('maserKeySync', self.masterKeySync.bind(self));

};

SocketServer.prototype.updateMasterKeyPair = function updateMasterKeyPair(callback) {
  var self = this;
  KeyPair.checkMasterKeyPairForAllUsers(function(err, response) {
    console.log("Checked master key pair for all users. Response is '"+response+"'");
    if (err) { console.log("[START] Error checking master key for all users: "+err); };
    if (response == 'update') {
      console.log("Users keypair needs updating so generating new master key pair");
      KeyPair.regenerateMasterKeyPair(function(err, masterKeyPair, id) {
        console.log("[START] New master keyPair generated with id '"+id+"'");
        KeyPair.updateMasterKeyPairForAllUsers(masterKeyPair, id, function(err) {
          if (err) {
            console.log("[START] Error encrypting master key for all users: "+err);
            return callback(err);
          };
          console.log("[*2*] [START] Encrypted master key for all users!");
          self.namespace.emit('newMasterKey', { masterKeyPair: masterKeyPair } );
          callback(null);
        });
      });
    } else if (response == 'ok') {
      console.log("All users master key matches current version");
      //self.namespace.emit('newMasterKey');
      callback(null);
    }
  });
};

SocketServer.prototype.start = function start() {
  var self = this;
  this.updateMasterKeyPair();
};

/**
 * New socket connected to server
 */
SocketServer.prototype.authenticate = function init(data) {
  var self = this;
  console.log("[AUTHENTICATE] Authenticating user '"+data.userName+"'");
  User.authenticateOrCreate(data, function(err, user) {
    if (err) {
      console.log('Authentication error', err);
      return self.socket.emit('errorMessage', {message: 'Error authenticating you ' + err});
    }
    if (user) {
      self.namespace.socketMap[self.socket.id] = {
        userName: user.userName,
        publicKey: user.publicKey
      };

      self.namespace.userMap[user.userName] = self.socket.id;

      self.socket.user = user;
      console.log("[INIT] Init'd user " + user.userName);
      // TODO: This doesn't seem to get to the client
      self.socket.emit('authenticated', {message: 'ok'});

      console.log("[INIT] Emitting user connect");
      //return self.namespace.emit('user connect', {
      return self.namespace.emit('user connect', {
        userName: user.userName,
        publicKey: user.publicKey
      });
    }
    else {
      console.log("[INIT] Problem initializing connection, no error, but no user");
      return self.socket.emit('errorMessage', {message: "An unknown error has occurred"});
    }
  });
};

/**
 * Check and sync master key for user
 */
SocketServer.prototype.masterKeySync = function masterKeySync(data) {
  var currentKeyId = data.currentKeyId;

};

SocketServer.prototype.updateClientKey = function updateClientKey(data) {

};

/**
 * Message broadcast from client
 */
SocketServer.prototype.onMessage = function onMessage(data) {
  var self = this;

  if (!self.socket.user) {
    console.log("[MSG] Ignoring message from unauthenticated user");
    return self.socket.emit('errorMessage', {message: 401});
  }

  console.log("[MSG] Server got chat message from " + self.socket.user.userName);

  //TODO: Log messages
  //TODO: Room specific messages
  self.namespace.emit('roomMessage', {
    user: self.socket.user.userName,
    message: data.pgpMessage,
    signature: data.signature
  });

  console.log("[MSG] Server emitted chat message to users");
};


/**
 * Private message from client
 */
SocketServer.prototype.onPrivateMessage = function onPrivateMessage(data) {
  var self = this;
  if (!self.socket.user) {
    console.log("[MSG] Ignoring message from unauthenticated user");
    return self.socket.emit('errorMessage', {message: 401});
  }
  console.log('data', data)

  var fromUser = self.socket.user.userName;
  var targetUsername = data.toUser;
  var targetSocket = self.namespace.userMap[targetUsername];

  if (!targetSocket) {
    console.log("[MSG] Ignoring private message to offline user");
    return self.socket.emit('errorMessage', {message: "User is not online"});
  }

  self.socket.broadcast.to(targetSocket).emit('privateMessage', {
    from: self.socket.user.userName,
    to: targetUsername,
    message: data.pgpMessage,
    signature: data.signature
  });
};

SocketServer.prototype.onServerCommand = function onServerCommand(data) {
  var socket = this.socket;
  var command = data.command;
  //TODO refactor this
  var currentChannel = data.currentChannel;
  console.log("Received command '"+command+"' from user '"+socket.name+"'");
  var splitCommand = command.split(" ");
  if (splitCommand[0] == "who") {
    console.log("[SERVER] Responding to 'who' request from '"+socket.name+"'");
    var channelMembershipArray = [];
    console.log("[SERVER COMMAND] Checking channel #"+currentChannel);
    for (var key in channelMembership[currentChannel]) {
      console.log("[SERVER COMMAND] Iterating user "+channelMembership[currentChannel][key].username);
      channelMembershipArray.push(channelMembership[currentChannel][key].username);
    }
    console.log("[SERVER COMMAND] Broadcasting user list for #"+currentChannel+" to socket.id "+socket.id+" with data ( "+channelMembershipArray.toString()+" )");
    this.namespace.to(socket.id).emit('chat status', { statusType: "WHO", statusMessage: "Current users of #"+currentChannel+" are ( "+channelMembershipArray.toString()+" )"});
    //socket.broadcast.to(socket.id).emit('chat status', "Current users of #"+currentChannel+" are ( "+channelMembershipArray.toString()+" )");
  } else if (splitCommand[0] == "help") {
    // Output help here
  } else {
    console.log("[SERVER COMMAND] Unable to parse server command...");
  }
};


/**
 * Client join channel
 */
SocketServer.prototype.joinChannel = function joinChannel(data) {
  var self = this;
  console.log("User '"+data.userName+"' joining channel #"+data.channel);

  if (!self.socket.user) {
    console.log("Ignoring join attempt by unauthenticated user");
    return self.socket.emit('errorMessage', {message: 401});
  }

  var userName = self.socket.user.userName;
  var channel = data.channel;
  // Ensure that user has the most recent master key for this channel if in masterKey mode
  if (config.encryptionScheme == 'masterKey') {
    console.log("[JOIN CHANNEL] encryptionScheme: masterKey - checking masterKey - masterKeyId: "+data.masterKeyId);
    var usersMasterKeyId = data.masterKeyId;
    KeyId.getMasterKeyId(function(err, currentKeyId) {
      console.log("[JOIN CHANNEL] currentKeyId: "+currentKeyId);
      // TODO: User gets updated master key here but we still may need to trigger generating a new one for the user if it has not been generated for them yet. This might be when users are added to the membership of a channel, or when a user updates their public key and then that key is approved by an admin
      if (usersMasterKeyId !== currentKeyId) {
        self.updateMasterKeyPair(function(err) {
          console.log("[*3*] [JOIN CHANNEL] Clients master key is not up to date, emitting 'newMasterKey'");
          self.socket.emit('newMasterKey', { keyId: currentKeyId });
          self.socket.join(channel);
          self.updateUserList(channel);
        });
      } else {
        console.log("[JOIN CHANNEL] Clients master key is up to date");
        self.socket.join(channel);
        self.updateUserList(channel);
      };
    });
  } else {
    // Using client key encryption scheme
    self.socket.join(channel);
    self.updateUserList(channel);
  };
};

/**
 * Update userlist for a channel
 */
SocketServer.prototype.updateUserList = function updateUserList(channel) {
  var self = this;
  var userName = self.socket.user.userName;
  self.getUserList(channel, function(err, users) {
    self.namespace.to(channel).emit("userlist update", {
      joinUser: userName,
      channel: channel,
      userList: users
    });
  });
};

/**
 * Socket leave channel
 */
SocketServer.prototype.leaveChannel = function leaveChannel(data) {
  //TODO: flush out
  this.socket.leave(data.channel);
};

SocketServer.prototype.disconnect = function disconnect() {
  var self = this;
  if (!self.socket) {
    return console.log("unknown socket");
  }

  console.log("[DISCONNECT] socket.id: " + self.socket.id);

  console.log("[DISCONNECT] looping rooms...");
  self.socket.rooms.forEach( function(room) {
    console.log("[LEAVE CHANNEL] Room: "+room);
  });
  delete self.namespace.socketMap[self.socket.id];

  if (self.socket.user && self.socket.user.userName) {
    delete self.namespace.userMap[self.socket.user.userName];
  }
};

SocketServer.prototype.getUserList = function(room, callback) {
  var self = this;
  var members = [];
  console.log("[SOCKETSERVER] Room: "+room);

  //Get all sockets in this room
  //TODO: This fails when server restarted with users connected
  if (typeof this.namespace.adapter.rooms[room] !== 'undefined') {
    var members = this.namespace.adapter.rooms[room];
    members = Object.keys(this.namespace.adapter.rooms[room]).filter(function(sid) {
      return members[sid];
    });

    //Map sockets to users
    members = members.map(function(sid) {
      return self.namespace.socketMap[sid];
    });
  } else {
    console.log("[GET USER LIST] User list is empty");
  };

  callback(null, members);
};


//TODO: Are these still needed?
SocketServer.prototype.sendUserListUpdate = function sendUserListUpdate(channel, callback) {
  if (channel != null) {
    getChannelUsersArray(channel, function(err, channelUsersArray) {
      if (err) {
        callback(err);
      } else {
        var userListData = {
          userList: channelUsersArray
        }
        ioMain.emit("userlist update", userListData);
        callback(null);
      };
    });
  } else {
    // update all channels
  };
};

SocketServer.prototype.removeUserFromAllChannels = function removeUserFromAllChannels(socketId, callback) {
  var userName = "";
  // TODO: fix me!
  findUserBySocketId(socketId, function(err, user) {
    if (err) {
      callback(err, null);
    } else {
      Channel.update({}, { $pull: { _userList: user.id } }, function(err, channel, count) {
        if (err) {
          callback(err, null);
        } else {
          console.log("Removed "+user.userName+" from "+count+" channels");
          callback(null, userName);
        };
      });
    };
  });
};

//TODO: Decide to use this method or use the socket namespaces
SocketServer.prototype.findClientsSocket = function findClientsSocket(roomId, namespace) {
    var res = [];
    var ns = io.of(namespace ||"/");    // the default namespace is "/"
    if (ns) {
        for (var id in ns.connected) {
            if(roomId) {
                var index = ns.connected[id].rooms.indexOf(roomId) ;
                if(index !== -1) {
                    res.push(ns.connected[id]);
                }
            } else {
                res.push(ns.connected[id]);
            }
        }
    }
    return res;
}

SocketServer.prototype.findClientsSocketByRoomId = function findClientsSocketByRoomId(roomId) {
  var res = [];
  var room = io.sockets.adapter.rooms[roomId];
  if (room) {
    for (var id in room) {
      res.push(io.sockets.adapter.nsp.connected[id]);
    };
  };
  return res;
};

module.exports = SocketServer;
