'use strict';
var brorand   = require('brorand');
var hashjs    = require('hash.js');
var EC        = require('elliptic').ec;
var ec        = new EC('secp256k1');
var secp256k1 = require('./secp256k1');
var hexToBytes = require('./utils').hexToBytes;
var bytesToHex = require('./utils').bytesToHex;
var seqEqual = require('./utils').seqEqual;

var SEED_PREFIX = 33;
var ACCOUNT_PREFIX = 0;
var alphabet = 'jpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65rkm8oFqi1tuvAxyz';
var base58 = require('base-x')(alphabet);

// you know it
function sha256(bytes) {
	return hashjs.sha256().update(bytes).digest();
}

/**
 * concat an item and a buffer
 * @param {integer} item1, should be an integer
 * @param {buffer} buf2, a buffer
 * @returns {buffer} new Buffer
 */
function bufCat0(item1, buf2) {
    var buf = Buffer.alloc(1 + buf2.length);
    buf[0] = item1;
    for(var i = 0; i < buf2.length; i++){
        buf[i+1] = buf2[i];
    }
    // buf2.copy(buf, 1);//前端没有copy方法
    return buf;
    // return Buffer.concat([Buffer.from([item1]), buf2]);//前端解析出错
}

/**
 * encode use jingtum base58 encoding
 * including version + data + checksum
 * @param {integer} version
 * @param {buffer} bytes
 * @returns {string}
 * @private
 */
function __encode(bytes, version) {
    var buffer = bufCat0(version || ACCOUNT_PREFIX, bytes);
    var checksum = Buffer.from(sha256(sha256(buffer)).slice(0, 4));
    var ret = Buffer.concat([buffer, checksum]);
    return base58.encode(ret);
}


/**
 * decode encoded input,
 * 	too small or invalid checksum will throw exception
 * @param {integer} version
 * @param {string} input
 * @returns {buffer}
 * @private
 */
function __decode(input, version) {
    var bytes = base58.decode(input);
    if (!bytes || bytes[0] !== (version || ACCOUNT_PREFIX) || bytes.length < 5) {
        throw new Error('invalid input size');
    }
    var computed = sha256(sha256(bytes.slice(0, -4))).slice(0, 4);
    var checksum = bytes.slice(-4);
    for (var i = 0; i !== 4; i += 1) {
        if (computed[i] !== checksum[i])
            throw new Error('invalid checksum');
    }
    return bytes.slice(1, -4);
}

exports.__encode = __encode;
exports.__decode = __decode;

/**
 * generate random bytes and encode it to secret
 * @returns {string}
 */
exports.generateSeed = function() {
    var randBytes = brorand(16);
    return __encode(randBytes, SEED_PREFIX);
};

/**
 * generate privatekey from input seed
 * one seed can generate many keypairs,
 * here just use the first one
 * @param {buffer} seed
 * @returns {buffer}
 */
function derivePrivateKey(seed) {
  var order = ec.curve.n;
  var privateGen = secp256k1.ScalarMultiple(seed);
  var publicGen = ec.g.mul(privateGen);
  return secp256k1.ScalarMultiple(publicGen.encodeCompressed(), 0).add(privateGen).mod(order);
}

function verifyCheckSum(bytes) {
    var computed = sha256(sha256(bytes.slice(0, -4))).slice(0, 4);
    var checksum = bytes.slice(-4);
    return seqEqual(computed, checksum);
}
/**
 * derive keypair from secret
 * @param {string} secret
 * @returns {{privateKey: string, publicKey: *}}
 */
exports.deriveKeyPair = function(secret) {
	var prefix = '00';
	var buf = base58.decode(secret);

	if(!buf || buf[0] !== SEED_PREFIX || buf.length < 5){
        throw new Error('invalid_input_size');
    }
    if (!verifyCheckSum(buf)) {
        throw new Error('checksum_invalid');
    }
    var entropy = buf.slice(1, -4);
	var privateKey = prefix + derivePrivateKey(entropy).toString(16, 64).toUpperCase();
	var publicKey = bytesToHex(ec.keyFromPrivate(privateKey.slice(2)).getPublic().encodeCompressed());
	return { privateKey: privateKey, publicKey: publicKey };
};

/**
 * devive keypair from privatekey
 */
exports.deriveKeyPairWithKey = function(key) {
	var privateKey = key;
	var publicKey = bytesToHex(ec.keyFromPrivate(key).getPublic().encodeCompressed());
	return { privateKey: privateKey, publicKey: publicKey };
};


/**
 * derive wallet address from publickey
 * @param {string} publicKey
 * @returns {string}
 */
exports.deriveAddress = function(publicKey) {
	var bytes = hexToBytes(publicKey);
	var hash256 = hashjs.sha256().update(bytes).digest();
    var input = new Buffer(hashjs.ripemd160().update(hash256).digest());
    return __encode(input);
};

/**
 * check is address is valid
 * @param address
 * @returns {boolean}
 */
exports.checkAddress = function(address) {
    try {
        __decode(address);
        return true;
    } catch (err) {
        return false;
    }
};

/**
 * convert the input address to byte array
 *
 * @param address
 * @returns byte array
 */
exports.convertAddressToBytes  = function(address) {
    try {
        return __decode(address);

    } catch (err) {
        throw new Error('convertAddressToBytes error!');
    }
};

/*
 * Convert a byte array to a wallet address string
 *
*/
//Wallet.prototype.convertBytesToAddress= function(bytes) {
exports.convertBytesToAddress= function(bytes) {
    try {
        return __encode(bytes);

    } catch (err) {
        throw new Error('convertBytesToAddress error!');
    }
};
