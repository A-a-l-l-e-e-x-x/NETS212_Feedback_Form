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
// Error building function
var mkErr = function(status, type, message) {
	return {status: status, type: type, error: message};
};
// Logging utility (Currently console - Should log to database in future)
var log = function(type, message) { // Should log more than just a message...
	console.log(`[${Date.now()}][${type}]${message}`);
};
// Get list of all instructors
var get_instructors = () => {
	// So few instructors that the query structure of this code literally does not matter
	return new Promise((resolve, reject) => {
		Instructors.scan().loadAll().exec(function(err, result){
			if (err) {
				reject(mkErr(500, cfg.logging.type.dberr, 'Couldn\'t load instructors: ' + err));
				return;
			}
			resolve(result);
		});
	});
};
// Get single instructor, check secret match if private_key provided
let get_instructor = (instructor, pk) => {
	return new Promise((resolve, reject) => {
		Instructors.get(instructor, function(err, instr) {
			// Reject if DB fail
			if (err) {
				reject(mkErr(500, cfg.logging.type.dberr, `Error#6 querying instructors: ${err}`));
				return;
			}
			// If no private key was provided, instantly resolve (no secret check)
			if (! pk) {
				resolve(instr);
				return;
			}
			// Decrypt secret to see if private key is correct
			const secret = decrypt_comment(instr.get('secret'), pk);
			if(secret != cfg.user.secret) {
				reject(mkErr(403, cfg.logging.type.input, `Error#101 wrong key specified`));
				return;
			}
			resolve(instr);
		});
	});
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
				reject(mkErr(500, cfg.logging.type.dberr, `Error#3 querying comments: ${err}`));
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
app.get('/instructors', async function(req, res) {
	// Query all instructors
	try {
		const instructors = await get_instructors();
		// Send back names only
		res.send(instructors.Items.map(item => item.get('name')));
	} catch (exception) {
		// DB fail
		res.status(exception.status).send();
	}
});

// View page to select instructor and submit review
app.get('/', function(req, res) {
	res.sendFile(path.join(__dirname + '/send_feedback.html'));
});

// Submit instructor feedback (Check length)
app.post('/submit_feedback', async function(req, res){
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
	try {
		// Query the appropriate instructor to get public key (No key match needed)
		const instr = await get_instructor(name);
		// Encode the comment with the given public key
		var encrypted_comment = encrypt_comment(comment, instr.get('public_key'));
		if(encrypted_comment == null)
			encrypted_comment = 'Couldn\'t encrypt comment.';
		// Store the comment in the database
		await new Promise((resolve, reject) => {
			Feedback.create({instructor: name, comment: encrypted_comment}, function(err, data){
				if(err) {
					reject(mkErr(500, cfg.logging.type.dberr, `Error#2 creating comment: ${err}`));
					return;
				}
				resolve();
			});
		});
		res.status(200).send();
	} catch (exception) {
		log(exception.type, exception.error);
		res.status(exception.status).send();
	}
});

// View page to identify as instructor and specify private key to view reviews 
app.get('/view_feedback', function(req, res) {
	res.sendFile(path.join(__dirname + '/view_feedback.html'));
});

// Send back all reviews for given instructor decrypted with given key
app.post('/query_feedback', async function(req, res){
	// Post parameters
	const instructor = req.body.name;
	const private_key = req.body.private_key;
	
	// Query the feedback the TA has received
	try {
		var comments = await decrypted_comments(instructor, private_key);
		res.status(200).send(comments.map(item => item.comment));
	} catch (exception) {
		log(exception.type, exception.error);
		res.status(exception.status).send();
	}
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
					return;
				}
				resolve({public_key: npublic, private_key: nprivate});
			});
		});
	};
	
	try {
		// Query the current instructor and check if secret is correct
		log(cfg.logging.type.info, 'Querying appropriate instructor.');
		const instr = await get_instructor(instructor, post_private_key);
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
						return;
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
				return;
			}
			// Actually update
			Instructors.update({name: instr.get('name'), secret: new_secret, public_key: public_key}, function(err, i){
				if (err) {
					reject({status: 500, type: cfg.logging.type.dberr, error: `Error#11 update instr: ${err}`});
					return;
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