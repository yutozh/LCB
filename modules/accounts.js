var crypto = require('crypto');
var	bignum = require('../helpers/bignum.js');
var	ed = require('ed25519');
var	slots = require('../helpers/slots.js');
var	Router = require('../helpers/router.js');
var	util = require('util');
var	constants = require('../helpers/constants.js');
var	TransactionTypes = require('../helpers/transaction-types.js');
var	Diff = require('../helpers/diff.js');
var	util = require('util');
var	extend = require('extend');
var	sandboxHelper = require('../helpers/sandbox.js');
var async = require('async');

// private fields
var modules, library, self, privated = {}, shared = {};

function Vote() {
	this.create = function (data, trs) {
		trs.recipientId = data.sender.address;
		trs.recipientUsername = data.sender.username;
		trs.asset.votes = data.votes;

		return trs;
	};

	this.calculateFee = function (trs, sender) {
		return 0 * constants.fixedPoint;
	};

	this.verify = function (trs, sender, cb) {
		if (trs.recipientId != trs.senderId) {
			return setImmediate(cb, "Recipient is identical to sender");
		}

		if (!trs.asset.votes || !trs.asset.votes.length) {
			return setImmediate(cb, "Not enough spare votes available");
		}

		if (trs.asset.votes && trs.asset.votes.length > 33) {
			return setImmediate(cb, "Voting limited exceeded. Maxmium is 33 per transaction");
		}

		modules.delegates.checkDelegates(trs.senderPublicKey, trs.asset.votes, function (err) {
			setImmediate(cb, err, trs);
		});
	};

	this.process = function (trs, sender, cb) {
		setImmediate(cb, null, trs);
	};

	this.getBytes = function (trs) {
		try {
			var buf = trs.asset.votes ? new Buffer(trs.asset.votes.join(''), 'utf8') : null;
		} catch (e) {
			throw Error(e.toString());
		}

		return buf;
	};

	this.apply = function (trs, block, sender, cb) {
		this.scope.account.merge(sender.address, {
			delegates: trs.asset.votes,
			blockId: block.id,
			round: modules.round.calc(block.height)
		}, function (err) {
			cb(err);
		});
	};

	this.undo = function (trs, block, sender, cb) {
		if (trs.asset.votes === null) return cb();

		var votesInvert = Diff.reverse(trs.asset.votes);

		this.scope.account.merge(sender.address, {
			delegates: votesInvert,
			blockId: block.id,
			round: modules.round.calc(block.height)
		}, function (err) {
			cb(err);
		});
	};

	this.applyUnconfirmed = function (trs, sender, cb) {
		modules.delegates.checkUnconfirmedDelegates(trs.senderPublicKey, trs.asset.votes, function (err) {
			if (err) {
				return setImmediate(cb, err);
			}

			this.scope.account.merge(sender.address, {
				u_delegates: trs.asset.votes
			}, function (err) {
				cb(err);
			});
		}.bind(this));
	};

	this.undoUnconfirmed = function (trs, sender, cb) {
		if (trs.asset.votes === null) return cb();

		var votesInvert = Diff.reverse(trs.asset.votes);

		this.scope.account.merge(sender.address, {u_delegates: votesInvert}, function (err) {
			cb(err);
		});
	};

	this.objectNormalize = function (trs) {
		var report = library.scheme.validate(trs.asset, {
			type: "object",
			properties: {
				votes: {
					type: "array",
					minLength: 1,
					maxLength: 105,
					uniqueItems: true
				}
			},
			required: ['votes']
		});

		if (!report) {
			throw new Error("Incorrect votes in transactions: " + library.scheme.getLastError());
		}

		return trs;
	};

	this.dbRead = function (raw) {
		// console.log(raw.v_votes);

		if (!raw.v_votes) {
			return null;
		} else {
			var votes = raw.v_votes.split(',');

			return {votes: votes};
		}
	};

	this.dbSave = function (trs, cb) {
		library.dbLite.query("INSERT INTO votes(votes, transactionId) VALUES($votes, $transactionId)", {
			votes: util.isArray(trs.asset.votes) ? trs.asset.votes.join(',') : null,
			transactionId: trs.id
		}, cb);
	};

	this.ready = function (trs, sender) {
		if (sender.multisignatures.length) {
			if (!trs.signatures) {
				return false;
			}
			return trs.signatures.length >= sender.multimin - 1;
		} else {
			return true;
		}
	};
}

function LC_Vote() {
  this.create = function (data, trs) {
    trs.recipientId = data.sender.address;
    trs.recipientUsername = data.sender.username;
    trs.asset.lc_votes = data.lc_votes;

    return trs;
  };

  this.calculateFee = function (trs, sender) {
    return 0 * constants.fixedPoint;
  };

  this.verify = function (trs, sender, cb) {
    if (trs.recipientId != trs.senderId) {
      return setImmediate(cb, "Recipient is identical to sender");
    }

    if (!trs.asset.lc_votes || !trs.asset.lc_votes.length) {
      return setImmediate(cb, "Not enough spare votes available");
    }

    if (trs.asset.lc_votes && trs.asset.lc_votes.length > 33) {
      return setImmediate(cb, "Voting limited exceeded. Maxmium is 33 per transaction");
    }

    modules.lcs.checkLCs(trs.senderPublicKey, trs.asset.lc_votes, function (err) {
      setImmediate(cb, err, trs);
    });
  };

  this.process = function (trs, sender, cb) {
    setImmediate(cb, null, trs);
  };

  this.getBytes = function (trs) {
    try {
      var buf = trs.asset.lc_votes ? new Buffer(trs.asset.lc_votes.join(''), 'utf8') : null;
    } catch (e) {
      throw Error(e.toString());
    }

    return buf;
  };

  this.apply = function (trs, block, sender, cb) {
    this.scope.account.merge(sender.address, {
      lcs: trs.asset.lc_votes,
      blockId: block.id,
      round: modules.round.calc(block.height)
    }, function (err) {
      cb(err);
    });
  };

  this.undo = function (trs, block, sender, cb) {
    if (trs.asset.lc_votes === null) return cb();

    var votesInvert = Diff.reverse(trs.asset.lc_votes);

    this.scope.account.merge(sender.address, {
      lcs: votesInvert,
      blockId: block.id,
      round: modules.round.calc(block.height)
    }, function (err) {
      cb(err);
    });
  };

  this.applyUnconfirmed = function (trs, sender, cb) {
    modules.lcs.checkUnconfirmedLCs(trs.senderPublicKey, trs.asset.lc_votes, function (err) {
      if (err) {
        return setImmediate(cb, err);
      }

      this.scope.account.merge(sender.address, {
        u_lcs: trs.asset.lc_votes
      }, function (err) {
        cb(err);
      });
    }.bind(this));
  };

  this.undoUnconfirmed = function (trs, sender, cb) {
    if (trs.asset.lc_votes === null) return cb();

    var votesInvert = Diff.reverse(trs.asset.lc_votes);

    this.scope.account.merge(sender.address, {u_lcs: votesInvert}, function (err) {
      cb(err);
    });
  };

  this.objectNormalize = function (trs) {
    var report = library.scheme.validate(trs.asset, {
      type: "object",
      properties: {
        votes: {
          type: "array",
          minLength: 1,
          maxLength: 105,
          uniqueItems: true
        }
      },
      required: ['lc_votes']
    });

    if (!report) {
      throw new Error("Incorrect votes in transactions: " + library.scheme.getLastError());
    }

    return trs;
  };

  this.dbRead = function (raw) {
    // console.log(raw.v_votes);

    if (!raw.v_lc_votes) {
      return null;
    } else {
      var lc_votes = raw.v_lc_votes.split(',');

      return {lc_votes: lc_votes};
    }
  };

  this.dbSave = function (trs, cb) {
    library.dbLite.query("INSERT INTO lc_votes(lc_votes, transactionId) VALUES($votes, $transactionId)", {
      votes: util.isArray(trs.asset.lc_votes) ? trs.asset.lc_votes.join(',') : null,
      transactionId: trs.id
    }, cb);
  };

  this.ready = function (trs, sender) {
    if (sender.multisignatures.length) {
      if (!trs.signatures) {
        return false;
      }
      return trs.signatures.length >= sender.multimin - 1;
    } else {
      return true;
    }
  };
}

function LC_Auth() {
  this.create = function (data, trs) {
    trs.recipientId = data.sender.address;
    trs.recipientUsername = data.sender.username;
    trs.asset.lc_auth = data.lc_auth;

    return trs;
  };

  this.calculateFee = function (trs, sender) {
    return 0 * constants.fixedPoint;
  };

  this.verify = function (trs, sender, cb) {
    if (trs.recipientId != trs.senderId) {
      return setImmediate(cb, "Recipient is identical to sender");
    }

    if (!trs.asset.lc_auth || !trs.asset.lc_auth.length) {
      return setImmediate(cb, "Not enough spare votes available");
    }

    if (trs.asset.lc_auth && trs.asset.lc_auth.length > 33) {
      return setImmediate(cb, "Voting limited exceeded. Maxmium is 33 per transaction");
    }

    modules.lcs.checkAuth(trs.senderPublicKey, trs.asset.lc_auth, function (err) {
      setImmediate(cb, err, trs);
    });
  };

  this.process = function (trs, sender, cb) {
    setImmediate(cb, null, trs);
  };

  this.getBytes = function (trs) {
    try {
      var buf = trs.asset.lc_auth ? new Buffer(trs.asset.lc_auth.join(''), 'utf8') : null;
    } catch (e) {
      throw Error(e.toString());
    }

    return buf;
  };

  this.apply = function (trs, block, sender, cb) {
    this.scope.account.merge(sender.address, {
      auth: trs.asset.lc_auth,
      blockId: block.id,
      round: modules.round.calc(block.height)
    }, function (err) {
      cb(err);
    });
  };

  this.undo = function (trs, block, sender, cb) {
    if (trs.asset.lc_auth === null) return cb();

    var votesInvert = Diff.reverse(trs.asset.lc_auth);

    this.scope.account.merge(sender.address, {
      auth: votesInvert,
      blockId: block.id,
      round: modules.round.calc(block.height)
    }, function (err) {
      cb(err);
    });
  };

  this.applyUnconfirmed = function (trs, sender, cb) {
    modules.lcs.checkUnconfirmedAuth(trs.senderPublicKey, trs.asset.lc_auth, function (err) {
      if (err) {
        return setImmediate(cb, err);
      }

      this.scope.account.merge(sender.address, {
        u_auth: trs.asset.lc_auth
      }, function (err) {
        cb(err);
      });
    }.bind(this));
  };

  this.undoUnconfirmed = function (trs, sender, cb) {
    if (trs.asset.lc_auth === null) return cb();

    var votesInvert = Diff.reverse(trs.asset.lc_auth);

    this.scope.account.merge(sender.address, {u_auth: votesInvert}, function (err) {
      cb(err);
    });
  };

  this.objectNormalize = function (trs) {
    var report = library.scheme.validate(trs.asset, {
      type: "object",
      properties: {
        votes: {
          type: "array",
          minLength: 1,
          maxLength: 105,
          uniqueItems: true
        }
      },
      required: ['lc_auth']
    });

    if (!report) {
      throw new Error("Incorrect votes in transactions: " + library.scheme.getLastError());
    }

    return trs;
  };

  this.dbRead = function (raw) {
    // console.log(raw.v_votes);

		// ？？？？v_lc_auth
    if (!raw.v_lc_auth) {
      return null;
    } else {
      var lc_auth = raw.v_lc_auth.split(',');

      return {lc_auth: lc_auth};
    }
  };

  this.dbSave = function (trs, cb) {
    library.dbLite.query("INSERT INTO lc_auth(lc_auth, transactionId) VALUES($auth, $transactionId)", {
      auth: util.isArray(trs.asset.lc_auth) ? trs.asset.lc_auth.join(',') : null,
      transactionId: trs.id
    }, cb);
  };

  this.ready = function (trs, sender) {
    if (sender.multisignatures.length) {
      if (!trs.signatures) {
        return false;
      }
      return trs.signatures.length >= sender.multimin - 1;
    } else {
      return true;
    }
  };
}



function Username() {
	this.create = function (data, trs) {
		trs.recipientId = null;
		trs.amount = 0;
		trs.asset.username = {
			alias: data.username,
			publicKey: data.sender.publicKey
		};

		return trs;
	};

	this.calculateFee = function (trs, sender) {
		return 0 * constants.fixedPoint;
	};

	this.verify = function (trs, sender, cb) {
		if (trs.recipientId) {
			return setImmediate(cb, "Invalid recipient");
		}

		if (trs.amount !== 0) {
			return setImmediate(cb, "Invalid transaction amount");
		}

		if (!trs.asset.username.alias) {
			return setImmediate(cb, "Invalid transaction asset");
		}

		var allowSymbols = /^[a-z0-9!@$&_.]+$/g;
		if (!allowSymbols.test(trs.asset.username.alias.toLowerCase())) {
			return setImmediate(cb, "Username must only contain alphanumeric characters (with the exception of !@$&_)");
		}

		var isAddress = /^[0-9]+[L|l]$/g;
		if (isAddress.test(trs.asset.username.alias.toLowerCase())) {
			return setImmediate(cb, "Username cannot be a potential address");
		}

		if (trs.asset.username.alias.length === 0 || trs.asset.username.alias.length > 20) {
			return setImmediate(cb, "Invalid username length. Must be between 1 to 20 characters");
		}

		self.getAccount({
			$or: {
				username: trs.asset.username.alias,
				u_username: trs.asset.username.alias
			}
		}, function (err, account) {
			if (err) {
				return cb(err);
			}
			if (account && account.username == trs.asset.username.alias) {
				return cb("Username already exists");
			}
			if (sender.username && sender.username != trs.asset.username.alias) {
				return cb("Invalid username. Does not match transaction asset");
			}
			if (sender.u_username && sender.u_username != trs.asset.username.alias) {
				return cb("Account already has a username");
			}

			cb(null, trs);
		});
	};

	this.process = function (trs, sender, cb) {
		setImmediate(cb, null, trs);
	};

	this.getBytes = function (trs) {
		try {
			var buf = new Buffer(trs.asset.username.alias, 'utf8');
		} catch (e) {
			throw Error(e.toString());
		}

		return buf;
	};

	this.apply = function (trs, block, sender, cb) {
		self.setAccountAndGet({
			address: sender.address,
			u_username: null,
			username: trs.asset.username.alias,
			nameexist: 1,
			u_nameexist: 0
		}, cb);
	};

	this.undo = function (trs, block, sender, cb) {
		self.setAccountAndGet({
			address: sender.address,
			username: null,
			u_username: trs.asset.username.alias,
			nameexist: 0,
			u_nameexist: 1
		}, cb);
	};

	this.applyUnconfirmed = function (trs, sender, cb) {
		if (sender.username || sender.u_username) {
			return setImmediate(cb, "Account already has a username");
		}

		var address = modules.accounts.generateAddressByPublicKey(trs.senderPublicKey);

		self.getAccount({
			$or: {
				u_username: trs.asset.username.alias,
				address: address
			}
		}, function (err, account) {
			if (err) {
				return cb(err);
			}
			if (account && account.u_username) {
				return cb("Username already exists");
			}

			self.setAccountAndGet({address: sender.address, u_username: trs.asset.username.alias, u_nameexist: 1}, cb);
		});
	};

	this.undoUnconfirmed = function (trs, sender, cb) {
		self.setAccountAndGet({address: sender.address, u_username: null, u_nameexist: 0}, cb);
	};

	this.objectNormalize = function (trs) {
		var report = library.scheme.validate(trs.asset.username, {
			type: "object",
			properties: {
				alias: {
					type: "string",
					minLength: 1,
					maxLength: 20
				},
				publicKey: {
					type: 'string',
					format: 'publicKey'
				}
			},
			required: ['alias', 'publicKey']
		});

		if (!report) {
			throw Error(library.scheme.getLastError());
		}

		return trs;
	};

	this.dbRead = function (raw) {
		if (!raw.u_alias) {
			return null;
		} else {
			var username = {
				alias: raw.u_alias,
				publicKey: raw.t_senderPublicKey
			};

			return {username: username};
		}
	};

	this.dbSave = function (trs, cb) {
		library.dbLite.query("INSERT INTO usernames(username, transactionId) VALUES($username, $transactionId)", {
			username: trs.asset.username.alias,
			transactionId: trs.id
		}, cb);
	};

	this.ready = function (trs, sender) {
		if (sender.multisignatures.length) {
			if (!trs.signatures) {
				return false;
			}
			return trs.signatures.length >= sender.multimin - 1;
		} else {
			return true;
		}
	};
}

// Constructor
function Accounts(cb, scope) {
	library = scope;
	self = this;
	self.__private = privated;
	privated.attachApi();

	library.logic.transaction.attachAssetType(TransactionTypes.VOTE, new Vote());
	library.logic.transaction.attachAssetType(TransactionTypes.LC_VOTE, new LC_Vote());
	library.logic.transaction.attachAssetType(TransactionTypes.LC_AUTH, new LC_Auth());
	library.logic.transaction.attachAssetType(TransactionTypes.USERNAME, new Username());

	setImmediate(cb, null, self);
}

// private methods
privated.attachApi = function () {
	var router = new Router();

	router.use(function (req, res, next) {
		if (modules) return next();
		res.status(500).send({success: false, error: "Blockchain is loading"});
	});

	router.map(shared, {
		"post /open": "open",
		"get /getBalance": "getBalance",
		"get /getPublicKey": "getPublickey",
		"post /generatePublicKey": "generatePublickey",
		"get /delegates": "getDelegates",
		"get /delegates/fee": "getDelegatesFee",
		"put /delegates": "addDelegates",
		// MY LC
    "get /lcs": "getLCs",
    "get /lcs/fee": "getLCsFee",
    "put /lcs": "addLCs",
    "put /auth": "addLCsAuth",
		//
		"get /username/get": "getUsername",
		"get /username/fee": "getUsernameFee",
		"put /username": "addUsername",
		"get /": "getAccount",
		"get /all": "getAllAccount"
	});

	if (process.env.DEBUG && process.env.DEBUG.toUpperCase() == "TRUE") {
		router.get('/getAllAccounts', function (req, res) {
			return res.json({success: true, accounts: privated.accounts});
		});
	}

	if (process.env.TOP && process.env.TOP.toUpperCase() == "TRUE") {
		router.get('/top', function (req, res, next) {
			req.sanitize(req.query, {
				type: "object",
				properties: {
					limit: {
						type: "integer",
						minimum: 0,
						maximum: 100
					},
					offset: {
						type: "integer",
						minimum: 0
					}
				}
			}, function (err, report, query) {
				if (err) return next(err);
				if (!report.isValid) return res.json({success: false, error: report.issues});
				self.getAccounts({
					sort: {
						balance: -1
					},
					offset: query.offset,
					limit: query.limit
				}, function (err, raw) {
					if (err) {
						return res.json({success: false, error: err.toString()});
					}
					var accounts = raw.map(function (fullAccount) {
						return {
							address: fullAccount.address,
							username: fullAccount.username,
							balance: fullAccount.balance,
							publicKey: fullAccount.publicKey
						};
					});

					res.json({success: true, accounts: accounts});
				});
			});
		});
	}

	router.get('/count', function (req, res) {
		return res.json({success: true, count: Object.keys(privated.accounts).length});
	});

	router.use(function (req, res, next) {
		res.status(500).send({success: false, error: "API endpoint was not found"});
	});

	library.network.app.use('/api/accounts', router);
	library.network.app.use(function (err, req, res, next) {
		if (!err) return next();
		library.logger.error(req.url, err.toString());
		res.status(500).send({success: false, error: err.toString()});
	});
};

privated.openAccount = function (secret, cb) {
	var hash = crypto.createHash('sha256').update(secret, 'utf8').digest();
	var keypair = ed.MakeKeypair(hash);

	self.setAccountAndGet({publicKey: keypair.publicKey.toString('hex')}, cb);
};

// Public methods
Accounts.prototype.generateAddressByPublicKey = function (publicKey) {
	var publicKeyHash = crypto.createHash('sha256').update(publicKey, 'hex').digest();
	var temp = new Buffer(8);
	for (var i = 0; i < 8; i++) {
		temp[i] = publicKeyHash[7 - i];
	}

	var address = bignum.fromBuffer(temp).toString() + 'L';
	if (!address) {
		throw Error("wrong publicKey " + publicKey);
	}
	return address;
};

Accounts.prototype.getAccount = function (filter, fields, cb) {
	if (filter.publicKey) {
		filter.address = self.generateAddressByPublicKey(filter.publicKey);
		delete filter.publicKey;
	}

	library.logic.account.get(filter, fields, cb);
};

Accounts.prototype.getAllAccount = function (filter, fields, cb) {
  if (filter.publicKey) {
    filter.address = self.generateAddressByPublicKey(filter.publicKey);
    delete filter.publicKey;
  }

  library.logic.account.getAll(filter, fields, cb);
};

Accounts.prototype.getAccounts = function (filter, fields, cb) {
	library.logic.account.getAll(filter, fields, cb);
};

Accounts.prototype.setAccountAndGet = function (data, cb) {
	var address = data.address || null;
	if (address === null) {
		if (data.publicKey) {
			address = self.generateAddressByPublicKey(data.publicKey);
		} else {
			return cb("Missing address or public key");
		}
	}
	if (!address) {
		throw cb("Invalid public key");
	}
	library.logic.account.set(address, data, function (err) {
		if (err) {
			return cb(err);
		}
		library.logic.account.get({address: address}, cb);
	});
};

Accounts.prototype.mergeAccountAndGet = function (data, cb) {
	var address = data.address || null;
	if (address === null) {
		if (data.publicKey) {
			address = self.generateAddressByPublicKey(data.publicKey);
		} else {
			return cb("Missing address or public key");
		}
	}
	if (!address) {
		throw cb("Invalid public key");
	}
	library.logic.account.merge(address, data, cb);
};

Accounts.prototype.sandboxApi = function (call, args, cb) {
	sandboxHelper.callMethod(shared, call, args, cb);
};

// Events
Accounts.prototype.onBind = function (scope) {
	modules = scope;
};

// Shared
shared.open = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			secret: {
				type: "string",
				minLength: 1,
				maxLength: 100
			}
		},
		required: ["secret"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		privated.openAccount(body.secret, function (err, account) {
			var accountData = null;
			if (!err) {
				accountData = {
					address: account.address,
					unconfirmedBalance: account.u_balance,
					balance: account.balance,
					publicKey: account.publicKey,
					unconfirmedSignature: account.u_secondSignature,
					secondSignature: account.secondSignature,
					secondPublicKey: account.secondPublicKey,
					multisignatures: account.multisignatures,
					u_multisignatures: account.u_multisignatures
				};

				return cb(null, {account: accountData});
			} else {
				return cb(err);
			}
		});
	});
};

shared.getBalance = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			address: {
				type: "string",
				minLength: 1
			}
		},
		required: ["address"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		var isAddress = /^[0-9]+[L|l]$/g;
		if (!isAddress.test(query.address)) {
			return cb("Invalid address");
		}

		self.getAccount({address: query.address}, function (err, account) {
			if (err) {
				return cb(err.toString());
			}
			var balance = account ? account.balance : 0;
			var unconfirmedBalance = account ? account.u_balance : 0;

			cb(null, {balance: balance, unconfirmedBalance: unconfirmedBalance});
		});
	});
};

shared.getPublickey = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			address: {
				type: "string",
				minLength: 1
			}
		},
		required: ["address"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		self.getAccount({address: query.address}, function (err, account) {
			if (err) {
				return cb(err.toString());
			}
			if (!account || !account.publicKey) {
				return cb("Account does not have a public key");
			}
			cb(null, {publicKey: account.publicKey});
		});
	});
};

shared.generatePublickey = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			secret: {
				type: "string",
				minLength: 1
			}
		},
		required: ["secret"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		privated.openAccount(body.secret, function (err, account) {
			var publicKey = null;
			if (!err && account) {
				publicKey = account.publicKey;
			}
			cb(err, {
				publicKey: publicKey
			});
		});
	});
};

shared.getDelegates = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			address: {
				type: "string",
				minLength: 1
			}
		},
		required: ["address"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		self.getAccount({address: query.address}, function (err, account) {
			if (err) {
				return cb(err.toString());
			}
			if (!account) {
				return cb("Account not found");
			}

			if (account.delegates) {
				self.getAccounts({
					isDelegate: 1,
					sort: {"vote": -1, "publicKey": 1}
				}, ["username", "address", "publicKey", "vote", "missedblocks", "producedblocks", "virgin"], function (err, delegates) {
					if (err) {
						return cb(err.toString());
					}

					var limit = query.limit || 101,
						offset = query.offset || 0,
						orderField = query.orderBy,
						active = query.active;

					orderField = orderField ? orderField.split(':') : null;
					limit = limit > 101 ? 101 : limit;
					var orderBy = orderField ? orderField[0] : null;
					var sortMode = orderField && orderField.length == 2 ? orderField[1] : 'asc';
					var count = delegates.length;
					var length = Math.min(limit, count);
					var realLimit = Math.min(offset + limit, count);

					for (var i = 0; i < delegates.length; i++) {
						delegates[i].rate = i + 1;

						var percent = 100 - (delegates[i].missedblocks / ((delegates[i].producedblocks + delegates[i].missedblocks) / 100));
						percent = percent || 0;
						var outsider = i + 1 > constants.delegates && delegates[i].virgin;
						delegates[i].productivity = !outsider ? delegates[i].virgin ? 0 : parseFloat(Math.floor(percent * 100) / 100).toFixed(2) : null;
					}

					var result = delegates.filter(function (delegate) {
						return account.delegates.indexOf(delegate.publicKey) != -1;
					});

					cb(null, {delegates: result});
				});
			} else {
				cb(null, {delegates: []});
			}
		});
	});
};

shared.getDelegatesFee = function (req, cb) {
	var query = req.body;
	cb(null, {fee: 0 * constants.fixedPoint});
};

shared.addDelegates = function (req, cb) {
	var body = req.body;

	library.scheme.validate(body, {
		type: "object",
		properties: {
			secret: {
				type: 'string',
				minLength: 1
			},
			publicKey: {
				type: 'string',
				format: 'publicKey'
			},
			secondSecret: {
				type: 'string',
				minLength: 1
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		var hash = crypto.createHash('sha256').update(body.secret, 'utf8').digest();
		var keypair = ed.MakeKeypair(hash);

		if (body.publicKey) {
			if (keypair.publicKey.toString('hex') != body.publicKey) {
				return cb("Invalid passphrase");
			}
		}

		library.balancesSequence.add(function (cb) {
			if (body.multisigAccountPublicKey && body.multisigAccountPublicKey != keypair.publicKey.toString('hex')) {
				modules.accounts.getAccount({publicKey: body.multisigAccountPublicKey}, function (err, account) {
					if (err) {
						return cb(err.toString());
					}

					if (!account || !account.publicKey) {
						return cb("Multisignature account not found");
					}

					if (!account.multisignatures || !account.multisignatures) {
						return cb("Account does not have multisignatures enabled");
					}

					if (account.multisignatures.indexOf(keypair.publicKey.toString('hex')) < 0) {
						return cb("Account does not belong to multisignature group");
					}

					modules.accounts.getAccount({publicKey: keypair.publicKey}, function (err, requester) {
						if (err) {
							return cb(err.toString());
						}

						if (!requester || !requester.publicKey) {
							return cb("Invalid requester");
						}

						if (requester.secondSignature && !body.secondSecret) {
							return cb("Invalid second passphrase");
						}

						if (requester.publicKey == account.publicKey) {
							return cb("Invalid requester");
						}

						var secondKeypair = null;

						if (requester.secondSignature) {
							var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
							secondKeypair = ed.MakeKeypair(secondHash);
						}

						try {
							var transaction = library.logic.transaction.create({
								type: TransactionTypes.VOTE,
								votes: body.delegates,
								sender: account,
								keypair: keypair,
								secondKeypair: secondKeypair,
								requester: keypair
							});
						} catch (e) {
							return cb(e.toString());
						}
						modules.transactions.receiveTransactions([transaction], cb);
					});
				});
			} else {
				self.getAccount({publicKey: keypair.publicKey.toString('hex')}, function (err, account) {
					if (err) {
						return cb(err.toString());
					}
					if (!account || !account.publicKey) {
						return cb("Invalid account");
					}

					if (account.secondSignature && !body.secondSecret) {
						return cb("Invalid second passphrase");
					}

					var secondKeypair = null;

					if (account.secondSignature) {
						var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
						secondKeypair = ed.MakeKeypair(secondHash);
					}

					try {
						var transaction = library.logic.transaction.create({
							type: TransactionTypes.VOTE,
							votes: body.delegates,
							sender: account,
							keypair: keypair,
							secondKeypair: secondKeypair
						});
					} catch (e) {
						return cb(e.toString());
					}
					modules.transactions.receiveTransactions([transaction], cb);
				});
			}
		}, function (err, transaction) {
			if (err) {
				return cb(err.toString());
			}

			cb(null, {transaction: transaction[0]});
		});
	});
};

// MY LC 查询某帐号对LC的投票情况
shared.getLCs = function (req, cb) {
  var query = req.body;
  library.scheme.validate(query, {
    type: "object",
    properties: {
      address: {
        type: "string",
        minLength: 1
      }
    },
    required: ["address"]
  }, function (err) {
    if (err) {
      return cb(err[0].message);
    }

    self.getAccount({address: query.address}, function (err, account) {
      if (err) {
        return cb(err.toString());
      }
      if (!account) {
        return cb("Account not found");
      }

      if (!account.isDelegate){
      	return cb("The address is not a Delegate，Only Delegate Can Vote to LC")
			}

      if (account.lcs) {
        self.getAccounts({
          isLC: 1,
          sort: {"lc_vote": -1, "publicKey": 1}
        }, ["username", "address", "publicKey", "lc_vote", "missedblocks", "producedblocks", "virgin"], function (err, lcs) {
          if (err) {
            return cb(err.toString());
          }

          // var limit = query.limit || 101,
          var limit = query.limit,
            offset = query.offset || 0,
            orderField = query.orderBy,
            active = query.active;

          orderField = orderField ? orderField.split(':') : null;
          // limit = limit > 101 ? 101 : limit;
          var orderBy = orderField ? orderField[0] : null;
          var sortMode = orderField && orderField.length == 2 ? orderField[1] : 'asc';
          var count = lcs.length;
          var length = Math.min(limit, count);
          var realLimit = Math.min(offset + limit, count);

          for (var i = 0; i < lcs.length; i++) {
            lcs[i].rate = i + 1;

            // var percent = 100 - (lcs[i].missedblocks / ((lcs[i].producedblocks + lcs[i].missedblocks) / 100));
            // percent = percent || 0;
            // var outsider = i + 1 > constants.delegates && lcs[i].virgin;
            // lcs[i].productivity = !outsider ? lcs[i].virgin ? 0 : parseFloat(Math.floor(percent * 100) / 100).toFixed(2) : null;
          }

          var result = lcs.filter(function (lc) {
            return account.lcs.indexOf(lc.publicKey) != -1;
          });

          cb(null, {lcs: result});
        });
      } else {
        cb(null, {lcs: []});
      }
    });
  });
};

shared.getLCsFee = function (req, cb) {
  var query = req.body;
  cb(null, {fee: 0 * constants.fixedPoint});
};

shared.addLCs = function (req, cb) {
  var body = req.body;

  library.scheme.validate(body, {
    type: "object",
    properties: {
      secret: {
        type: 'string',
        minLength: 1
      },
      publicKey: {
        type: 'string',
        format: 'publicKey'
      },
      secondSecret: {
        type: 'string',
        minLength: 1
      }
    }
  }, function (err) {
    if (err) {
      return cb(err[0].message);
    }

    var hash = crypto.createHash('sha256').update(body.secret, 'utf8').digest();
    var keypair = ed.MakeKeypair(hash);

    if (body.publicKey) {
      if (keypair.publicKey.toString('hex') != body.publicKey) {
        return cb("Invalid passphrase");
      }
    }

    library.balancesSequence.add(function (cb) {
      if (body.multisigAccountPublicKey && body.multisigAccountPublicKey != keypair.publicKey.toString('hex')) {
        modules.accounts.getAccount({publicKey: body.multisigAccountPublicKey}, function (err, account) {
          if (err) {
            return cb(err.toString());
          }

          if (!account || !account.publicKey) {
            return cb("Multisignature account not found");
          }

          if (!account.multisignatures || !account.multisignatures) {
            return cb("Account does not have multisignatures enabled");
          }

          if (account.multisignatures.indexOf(keypair.publicKey.toString('hex')) < 0) {
            return cb("Account does not belong to multisignature group");
          }

          modules.accounts.getAccount({publicKey: keypair.publicKey}, function (err, requester) {
            if (err) {
              return cb(err.toString());
            }

            if (!requester || !requester.publicKey) {
              return cb("Invalid requester");
            }

            if (requester.secondSignature && !body.secondSecret) {
              return cb("Invalid second passphrase");
            }

            // MY LC
            if (!requester.isDelegate){
              return cb("Only Delegate Can Vote to LC")
            }

            if (requester.publicKey == account.publicKey) {
              return cb("Invalid requester");
            }

            var secondKeypair = null;

            if (requester.secondSignature) {
              var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
              secondKeypair = ed.MakeKeypair(secondHash);
            }

            try {
              var transaction = library.logic.transaction.create({
                type: TransactionTypes.LC_VOTE,
                lc_votes: body.lcs,
                sender: account,
                keypair: keypair,
                secondKeypair: secondKeypair,
                requester: keypair
              });
            } catch (e) {
              return cb(e.toString());
            }

            modules.transactions.receiveTransactions([transaction], cb);
          });
        });
      } else {
        self.getAccount({publicKey: keypair.publicKey.toString('hex')}, function (err, account) {
          if (err) {
            return cb(err.toString());
          }
          if (!account || !account.publicKey) {
            return cb("Invalid account");
          }

          if (account.secondSignature && !body.secondSecret) {
            return cb("Invalid second passphrase");
          }

          // MY LC
					// 是否申请了delegate
          if (!account.isDelegate){
            return cb("Only Delegate Can Vote to LC")
          }

          // 是否为前101名
          modules.accounts.getAccounts({
            isDelegate: 1,
            limit: 101,
            // offset: query.offset,
            sort: {"vote": -1, "publicKey": 1}
          }, ["username", "address", "lcs"], function (err, delegates) {
            if (err) {
              return cb(err.toString());
            }

            let is101Delegate = false
            for (var i = 0; i < delegates.length; i++) {
              if(delegates[i].address === account.address){
                is101Delegate = true
								break
							}
            }
            if(!is101Delegate){
              return cb("Only Delegate who rank <=101 Can Vote to LC")
            }

            var secondKeypair = null;

            if (account.secondSignature) {
              var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
              secondKeypair = ed.MakeKeypair(secondHash);
            }

            try {
              var transaction = library.logic.transaction.create({
                type: TransactionTypes.LC_VOTE,
                lc_votes: body.lcs,
                sender: account,
                keypair: keypair,
                secondKeypair: secondKeypair
              });
            } catch (e) {
              return cb(e.toString());
            }
            modules.transactions.receiveTransactions([transaction], cb);
          });

        });
      }
    }, function (err, transaction) {
      if (err) {
        return cb(err.toString());
      }

      cb(null, {transaction: transaction[0]});
    });
  });
};

shared.addLCsAuth = function (req, cb) {
  var body = req.body;

  library.scheme.validate(body, {
    type: "object",
    properties: {
      secret: {
        type: 'string',
        minLength: 1
      },
      publicKey: {
        type: 'string',
        format: 'publicKey'
      },
      secondSecret: {
        type: 'string',
        minLength: 1
      }
    }
  }, function (err) {
    if (err) {
      return cb(err[0].message);
    }

    var hash = crypto.createHash('sha256').update(body.secret, 'utf8').digest();
    var keypair = ed.MakeKeypair(hash);

    if (body.publicKey) {
      if (keypair.publicKey.toString('hex') != body.publicKey) {
        return cb("Invalid passphrase");
      }
    }

		async.eachSeries(body.auth, function (action, cb) {
      var math = action[0];

      if (math !== '+' && math !== '-') {
        return cb("Invalid math operator");
      }

      var publicKey = action.slice(1);

      try {
        new Buffer(publicKey, "hex");
      } catch (e) {
        return cb("Invalid public key");
      }


			modules.accounts.getAccount({publicKey: publicKey}, function (err, account) {
				if (err) {
					return cb(err.toString());
				}
				if (!account || !account.publicKey) {
					return cb("Invalid account");
				}

				// MY LC
				if (!account.isLC){
					return cb("Only Can Auth to a LC")
				}

				cb()
			})
		}, function (err, res) {
			if(err){
				return cb(err)
			}
      library.balancesSequence.add(function (cb) {
        if (body.multisigAccountPublicKey && body.multisigAccountPublicKey != keypair.publicKey.toString('hex')) {
          modules.accounts.getAccount({publicKey: body.multisigAccountPublicKey}, function (err, account) {
            if (err) {
              return cb(err.toString());
            }

            if (!account || !account.publicKey) {
              return cb("Multisignature account not found");
            }

            if (!account.multisignatures || !account.multisignatures) {
              return cb("Account does not have multisignatures enabled");
            }

            if (account.multisignatures.indexOf(keypair.publicKey.toString('hex')) < 0) {
              return cb("Account does not belong to multisignature group");
            }

            modules.accounts.getAccount({publicKey: keypair.publicKey}, function (err, requester) {
              if (err) {
                return cb(err.toString());
              }

              if (!requester || !requester.publicKey) {
                return cb("Invalid requester");
              }

              if (requester.secondSignature && !body.secondSecret) {
                return cb("Invalid second passphrase");
              }


              if (requester.publicKey == account.publicKey) {
                return cb("Invalid requester");
              }

              var secondKeypair = null;

              if (requester.secondSignature) {
                var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
                secondKeypair = ed.MakeKeypair(secondHash);
              }

              try {
                var transaction = library.logic.transaction.create({
                  type: TransactionTypes.LC_AUTH,
                  lc_auth: body.auth,
                  sender: account,
                  keypair: keypair,
                  secondKeypair: secondKeypair,
                  requester: keypair
                });
              } catch (e) {
                return cb(e.toString());
              }

              modules.transactions.receiveTransactions([transaction], cb);
            });
          });
        } else {
          self.getAccount({publicKey: keypair.publicKey.toString('hex')}, function (err, account) {
            if (err) {
              return cb(err.toString());
            }
            if (!account || !account.publicKey) {
              return cb("Invalid account");
            }

            if (account.secondSignature && !body.secondSecret) {
              return cb("Invalid second passphrase");
            }

            var secondKeypair = null;

            if (account.secondSignature) {
              var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
              secondKeypair = ed.MakeKeypair(secondHash);
            }

            try {
              var transaction = library.logic.transaction.create({
                type: TransactionTypes.LC_AUTH,
                lc_auth: body.auth,
                sender: account,
                keypair: keypair,
                secondKeypair: secondKeypair
              });
            } catch (e) {
              return cb(e.toString());
            }
            modules.transactions.receiveTransactions([transaction], cb);
          });
        }
      }, function (err, transaction) {
        if (err) {
          return cb(err.toString());
        }

        cb(null, {transaction: transaction[0]});
      });
    });
  });
};



shared.getUsernameFee = function (req, cb) {
	var query = req.body;
	cb(null, {fee: 0 * constants.fixedPoint});
};

shared.addUsername = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			secret: {
				type: "string",
				minLength: 1
			},
			publicKey: {
				type: "string",
				format: "publicKey"
			},
			secondSecret: {
				type: "string",
				minLength: 1
			},
			username: {
				type: "string",
				minLength: 1
			}
		},
		required: ['secret', 'username']
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		var hash = crypto.createHash('sha256').update(body.secret, 'utf8').digest();
		var keypair = ed.MakeKeypair(hash);

		if (body.publicKey) {
			if (keypair.publicKey.toString('hex') != body.publicKey) {
				return cb("Invalid passphrase");
			}
		}

		library.balancesSequence.add(function (cb) {
			if (body.multisigAccountPublicKey && body.multisigAccountPublicKey != keypair.publicKey.toString('hex')) {
				modules.accounts.getAccount({publicKey: body.multisigAccountPublicKey}, function (err, account) {
					if (err) {
						return cb(err.toString());
					}

					if (!account || !account.publicKey) {
						return cb("Multisignature account not found");
					}

					if (!account.multisignatures || !account.multisignatures) {
						return cb("Account does not have multisignatures enabled");
					}

					if (account.multisignatures.indexOf(keypair.publicKey.toString('hex')) < 0) {
						return cb("Account does not belong to multisignature group");
					}

					modules.accounts.getAccount({publicKey: keypair.publicKey}, function (err, requester) {
						if (err) {
							return cb(err.toString());
						}

						if (!requester || !requester.publicKey) {
							return cb("Invalid requester");
						}

						if (requester.secondSignature && !body.secondSecret) {
							return cb("Invalid second passphrase");
						}

						if (requester.publicKey == account.publicKey) {
							return cb("Incorrect requester");
						}

						var secondKeypair = null;

						if (requester.secondSignature) {
							var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
							secondKeypair = ed.MakeKeypair(secondHash);
						}

						try {
							var transaction = library.logic.transaction.create({
								type: TransactionTypes.USERNAME,
								username: body.username,
								sender: account,
								keypair: keypair,
								secondKeypair: secondKeypair,
								requester: keypair
							});
						} catch (e) {
							return cb(e.toString());
						}
						modules.transactions.receiveTransactions([transaction], cb);
					});
				});
			} else {
				self.getAccount({publicKey: keypair.publicKey.toString('hex')}, function (err, account) {
					if (err) {
						return cb(err.toString());
					}
					if (!account || !account.publicKey) {
						return cb("Invalid account");
					}

					if (account.secondSignature && !body.secondSecret) {
						return cb("Invalid second passphrase");
					}

					var secondKeypair = null;

					if (account.secondSignature) {
						var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
						secondKeypair = ed.MakeKeypair(secondHash);
					}

					try {
						var transaction = library.logic.transaction.create({
							type: TransactionTypes.USERNAME,
							username: body.username,
							sender: account,
							keypair: keypair,
							secondKeypair: secondKeypair
						});
					} catch (e) {
						return cb(e.toString());
					}
					modules.transactions.receiveTransactions([transaction], cb);
				});
			}

		}, function (err, transaction) {
			if (err) {
				return cb(err.toString());
			}

			cb(null, {transaction: transaction[0]});
		});
	});
};

shared.getAllAccount = function (req, cb) {
  var query = req.body;
  library.scheme.validate(query, {
    type: "object",
    properties: {
      address: {
        type: "string",
        minLength: 1
      }
    },
  }, function (err) {
    if (err) {
      return cb(err[0].message);
    }

    self.getAllAccount({}, function (err, account) {
      if (err) {
        return cb(err.toString());
      }
      if (!account) {
        return cb("Account not found");
      }

      cb(null, {
        // account: {
        // 	address: account.address,
        // 	username: account.username,
        // 	unconfirmedBalance: account.u_balance,
        // 	balance: account.balance,
        // 	publicKey: account.publicKey,
        // 	unconfirmedSignature: account.u_secondSignature,
        // 	secondSignature: account.secondSignature,
        // 	secondPublicKey: account.secondPublicKey,
        // 	multisignatures: account.multisignatures,
        // 	u_multisignatures: account.u_multisignatures,
        // 	vote: account.vote,
        // 	lc_vote: account.lc_vote,
        // 	auth: account.auth
        // }
        account:account,
				count:account.length ? account.length : 0
      });
    });
  });
}
shared.getAccount = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			address: {
				type: "string",
				minLength: 1
			}
		},
		required: ["address"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		self.getAccount({address: query.address}, function (err, account) {
			if (err) {
				return cb(err.toString());
			}
			if (!account) {
				return cb("Account not found");
			}

			cb(null, {
				// account: {
				// 	address: account.address,
				// 	username: account.username,
				// 	unconfirmedBalance: account.u_balance,
				// 	balance: account.balance,
				// 	publicKey: account.publicKey,
				// 	unconfirmedSignature: account.u_secondSignature,
				// 	secondSignature: account.secondSignature,
				// 	secondPublicKey: account.secondPublicKey,
				// 	multisignatures: account.multisignatures,
				// 	u_multisignatures: account.u_multisignatures,
				// 	vote: account.vote,
				// 	lc_vote: account.lc_vote,
				// 	auth: account.auth
				// }
				account:account
			});
		});
	});
};

shared.getUsername = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			username: {
				type: "string",
				minLength: 1
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		self.getAccount({
			username: {$like: query.username.toLowerCase()}
		}, function (err, account) {
			if (err || !account) {
				return cb("Account not found");
			}

			cb(null, {
				account: {
					address: account.address,
					username: account.username,
					unconfirmedBalance: account.u_balance,
					balance: account.balance,
					publicKey: account.publicKey,
					unconfirmedSignature: account.u_secondSignature,
					secondSignature: account.secondSignature,
					secondPublicKey: account.secondPublicKey
				}
			});
		});
	});
};

// Export
module.exports = Accounts;
