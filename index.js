/*
 Import required libraries
*/
// DynamoDB (Database access)
const dynamo = require('dynamodb');
// Database schema validation
const Joi = require('joi');
// Express...
const express = require('express');
const app = express();
// Public/Private RSA Keys
var crypto = require("crypto");
// Configuration files
var path = require("path");
var cfg = require('./config/constants');

// TODO: Use input-sanitizing middleware

// Use JSON post parameters
app.use(express.urlencoded());

// Set-up connection with DynamoDB database
dynamo.AWS.config.update({accessKeyId: cfg.aws.access, secretAccessKey: cfg.aws.secret, region: cfg.aws.region});

/*
 Make sure DynamoDB tables are set up properly
*/
// Instructor table: Name, Public Key
var Instructors = dynamo.define('Instructor', {
	hashKey: 'name',
	schema: {
		name: Joi.string(),
		public_key: Joi.string(),
		secret: Joi.string() // Currently unused
	}
});
// Feedback table: Instructor, createdAt, Comment
var Feedback = dynamo.define('Feedback', {
	hashKey: 'instructor',
	rangeKey: 'createdAt',
	timestamps: true,
	schema: {
		instructor: Joi.string(),
		comment: Joi.string()
	}
});
// Create the tables if they haven't been yet
dynamo.createTables(function(err){
	if (err)
		log(cfg.logging.type.dberr, `Error in table creation: ${err}`);
	else
		log(cfg.logging.type.info, 'Tables created / loaded');
});

/*
 Util functions (Should be in different file, but this project is so small it really doesn't matter)
*/
// Logging utility (Currently console - Should log to database in future)
var log = function(type, message) { // Should log more than just a message...
	console.log(`[${Date.now()}][${type}]${message}`);
};
// Get list of instructors function
var get_instructors = function(callback) {
	// So few instructors that the query structure of this code literally does not matter
	Instructors.scan().loadAll().exec(callback);
};
// Decrypt comment
var decrypt_comment = function(comment, private_key) {
	var buffer = Buffer.from(comment, "base64");
	var decrypted = null;
	try {
		decrypted = crypto.privateDecrypt(private_key, buffer).toString("utf8");
	} catch (exception) {
		log(cfg.logging.type.crypto, `Couldn't decrypt comment: ${exception}`);
	}
	return decrypted;
};
// Encrypt comment
var encrypt_comment = function(plaintext, public_key) {
	const buffer = Buffer.from(plaintext);
	var encrypted_text = null;
	try {
		encrypted_text = crypto.publicEncrypt(public_key, buffer).toString("base64");
	} catch (exception) {
		log(cfg.logging.type.crypto, `Could not encrypt comment: ${exception}`);
	}
	return encrypted_text;
}
// Get all decrypted comments
var decrypted_comments = function(instructor_name, private_key) {
	// Return promise to be executed
	return new Promise((resolve, reject) => {
		Feedback.query(instructor_name).loadAll().exec(function(err, fb){
			// Query problem
			if (err) {
				reject({status: 500, type: cfg.logging.type.dberr, error: `Error#3 querying comments: ${err}`});
				return;
			}
			// Decrypt all comments
			resolve(fb.Items.map(item => {
				// For each comment, decrypt using private key
				var decrypted_comment = decrypt_comment(item.get('comment'), private_key);
				if(decrypted_comment == null)
					decrypted_comment = 'Provided key can\'t decrypt comment.';
				return {instructor: instructor_name, comment: decrypted_comment, createdAt: item.get('createdAt')};
			}));
		});
	});
};

/*
 Route serving
*/
// Make resources public
app.use(express.static('public'));

// Get list of instructors
app.get('/instructors', function(req, res) {
	get_instructors(function(err, result) {
		if(err) {
			log(cfg.logging.type.dberr, `Error#5 querying instructors: ${err}`);
			res.status(500).send({error: 'Backend error #5'});
			return;
		}
		res.send(result.Items.map(item => item.get('name')));
	});
});

// View page to select instructor and submit review
app.get('/', function(req, res) {
	res.sendFile(path.join(__dirname + '/send_feedback.html'));
});

// Submit instructor feedback (Check length)
app.post('/submit_feedback', function(req, res){
	// POST Parameters
	const name = req.body.name;
	const comment = req.body.comment;
	// Verify comment length
	if(comment.length < 15) {
		// TODO: Change appropriate error code
		log(cfg.logging.type.input, 'Error#100: Input comment not long enough.');
		res.status(500).send({error: 'Comment not long enough.'});
		return;
	}
	// Query the appropriate public key
	Instructors.get(name, function(err, instr){
		if (err) {
			log(cfg.logging.type.dberr, `Error#1 querying instructors: ${err}`);
			res.status(500).send();
			return;
		}
		// Encode the comment with the given public key
		var encrypted_comment = encrypt_comment(comment, instr.get('public_key'));
		if(encrypted_comment == null)
			encrypted_comment = 'Couldn\'t encrypt comment.';
		// Store the comment in the database
		Feedback.create({instructor: name, comment: encrypted_comment}, function(err, data){
			if(err) {
				log(cfg.logging.type.dberr, `Error#2 creating comment: ${err}`);
				res.status(500).send();
				return;
			}
			res.status(200).send();
		});
	});
});

// View page to identify as instructor and specify private key to view reviews 
app.get('/view_feedback', function(req, res) {
	res.sendFile(path.join(__dirname + '/view_feedback.html'));
});

// Send back all reviews for given instructor decrypted with given key
app.post('/query_feedback', function(req, res){
	// Post parameters
	const instructor = req.body.name;
	const private_key = req.body.private_key;
	
	// Query the feedback the TA has received
	Feedback.query(instructor).loadAll().exec(function(err, fb){
		// Query problem
		if (err) {
			log(cfg.logging.type.dberr, `Error#3 querying comments: ${err}`);
			res.status(500).send();
			return;
		}
		// Map items to readable format TODO refactor here as well
		res.status(200).send(fb.Items.map(item => {
			// For each comment, decrypt using private key
			var decrypted_comment = decrypt_comment(item.get('comment'), private_key);
			if(decrypted_comment == null)
				decrypted_comment = 'Provided key can\'t decrypt comment.';
			return decrypted_comment;
		}));
	});
});


// View page to generate new key pair for a given instructor, if instructor and current private key specified
app.get('/view_key', function(req, res){
	res.sendFile(path.join(__dirname + '/change_key.html'));
});

// Change current instructors public key if private key matches it
app.post('/change_key', async function(req, res) {
	log(cfg.logging.type.info, 'Attempting to change instructor key');
	// POST parameters
	const instructor = req.body.name;
	const post_private_key = req.body.private_key;
	
	// Query relevant instructor
	let get_instr = (instructor, pk) => {
		return new Promise((resolve, reject) => {
			Instructors.get(instructor, function(err, instr) {
				if (err) {
					reject({status: 500, type: cfg.logging.type.dberr, error: `Error#6 querying instructors: ${err}`});
				}
				// Decrypt secret to see if private key is correct
				const secret = decrypt_comment(instr.get('secret'), pk);
				if(secret != cfg.user.secret) {
					reject({status: 403, type: cfg.logging.type.input, error: `Error#101 wrong key specified`});
				}
				resolve(instr);
			});
		});
	};
	let gen_keys = () => {
		return new Promise((resolve, reject) => {
			// Generate new key
			// https://nodejs.org/api/crypto.html#crypto_crypto_generatekeypair_type_options_callback
			crypto.generateKeyPair('rsa', {
				modulusLength: 2048,
				publicKeyEncoding: {
					type: 'spki',
					format: 'pem'
				},
				privateKeyEncoding: {
					type: 'pkcs8',
					format: 'pem',
				}
			}, (err, npublic, nprivate) => {
				// Key generating failed?
				if(err) {
					reject({status: 500, type: cfg.logging.type.crypto, error: `Error#50 gen keys: ${error}`});
				}
				resolve({public_key: npublic, private_key: nprivate});
			});
		});
	};
	
	try {
		// Query the current instructor and check if secret is correct
		log(cfg.logging.type.info, 'Querying appropriate instructor.');
		const instr = await get_instr(instructor, post_private_key);
		// Generate a new key pair
		log(cfg.logging.type.info, 'Generating new key pair.');
		const { public_key, private_key } = await gen_keys();
		// Decrypt all comments of the given instructor
		log(cfg.logging.type.info, 'Decrypting all available comments');
		const comments = await decrypted_comments(instr.get('name'), post_private_key);
		// Encrypt all comments with the new public key
		log(cfg.logging.type.info, 'Re-encrypting all comments');
		const new_encrypted_comments = comments.map(comment => {
			// Encrypt the comment with the given public key
			var encrypted_comment = encrypt_comment(comment.comment, public_key);
			if(encrypted_comment == null)
				encrypted_comment = 'Couldn\'t encrypt comment.';
			// Replace the actual comment in the whole comment object
			comment.comment = encrypted_comment;
			// Actual comment has been updated within the object.
			return comment;
		});
		// Add promises to update all comments with the new encryption
		let nec_updates = new_encrypted_comments.map(comment => {
			return new Promise((resolve, reject) => {
				Feedback.update({instructor: instr.get('name'), createdAt: comment.createdAt, comment: comment.comment}, function(err, com){
					if (err) {
						reject({status: 500, type: cfg.logging.type.dberr, error: `Error#10 update comment: ${err}`});
					}
					resolve();
				});
			});
		});
		// Encrypt the new secret as well
		const new_secret = encrypt_comment(cfg.user.secret, public_key);
		// Update the secret and public_key of the instructor
		nec_updates.push(new Promise((resolve, reject) => {
			// If secret didn't get encrypted properly, fail.
			if (new_secret == null) {
				reject({status: 500, type: cfg.logging.type.crypto, error: 'Could\'nt encode secret.'});
			}
			// Actually update
			Instructors.update({name: instr.get('name'), secret: new_secret, public_key: public_key}, function(err, i){
				if (err) {
					reject({status: 500, type: cfg.logging.type.dberr, error: `Error#11 update instr: ${err}`});
				}
				resolve();
			});
		}));
		// Make sure all comments were updated successfully + secret & new key as well
		await Promise.all(nec_updates);
		// All promises passed - success, return the new key pair!
		res.status(200).send({publick: public_key, privatek: private_key});
	
	} catch (exception) {
		// Some promise in the try catch failed.
		log(exception.type, exception.error);
		res.status(exception.status).send();
	}
	
	
	/*Instructors.get(instructor, function(err, instr) {
		if (err) {
			log(cfg.logging.type.dberr, `Error#6 querying instructors: ${err}`);
			res.status(500).send();
			return;
		}
		if(public_key != instr.get('public_key')) {
			log(cfg.logging.type.input, `Error#101 wrong key specified`);
			res.status(403).send();
			return;
		}
		// If key matches:
		// Generate new key
		// https://nodejs.org/api/crypto.html#crypto_crypto_generatekeypair_type_options_callback
		crypto.generateKeyPair('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: {
				type: 'spki',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'pkcs8',
				format: 'pem',
			}
		}, (error, npublic, nprivate) => {
			// Key generating failed?
			if(error) {
				log(cfg.logging.type.crypto, `Error#50 gen keys: ${error}`);
				res.status(500).send();
				return;
			}
			// Query all comments, decrypt them, encrypt them with new key, update.
			Feedback.query(instructor).loadAll().exec(function(err, fb){
				// Query problem
				if (err) {
					log(cfg.logging.type.dberr, `Error#3 querying comments: ${err}`);
					res.status(500).send();
					return;
				}
				
			});
			// Save new key
			Instructors.update({name: instructor, public_key: npublic}, function(err, result){
				if (err) {
					console.log(err);
					res.status(500).send({error: 'Backend error #7'});
					return;
				}
				res.status(200).send({publick: npublic, privatek: nprivate});
			});
		});
		
	});*/
});

app.get('/s', function(req, res) {
	var k = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo/t4EW84YNfWuPjQfrnN
ov0yxuxBJ9y2QZAq9AnIS1Z4m2h+78SYmdYkrP1iMySH8XalDgLthXQ3aJvEKq46
ZvWzgZPYcegSciAkRbShy443teH2btKXfkhrOr0s8QciN0gKGR3XPB9XqK7wuCLe
HJBef0EOuf2sEK8iSg56DzB98PuppyhgihYKssCCQCjbx4UeJAGg68vu2ddlmrAW
1APS2tb6+dMwzenzRTU128DSZAkcLrJXZRNARTJtbBfazGqu0RTBEqexDUxHuEPA
FqeY/LEZ61c3GxO6mNSx5JHxnfsmYhI40LAb5D8BRIKJ0PIXnChn0dVSCi5qA7n4
BQIDAQAB
-----END PUBLIC KEY-----`;
	var c = encrypt_comment(cfg.user.secret, k);
	console.log(c);
	res.set('Content-Type', 'text/plain');
	res.send(c);
})

app.listen(3000, function () {
  console.log("Server started.");
});