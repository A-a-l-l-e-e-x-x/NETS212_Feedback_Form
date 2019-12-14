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
		secret: Joi.string()
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
		console.log('Error in table creation: ', err);
	else
		console.log('Tables created / loaded');
});

/*
 Database util functions (Should be in different file, but this project is so small it really doesn't matter)
*/
// Get list of instructors function
var get_instructors = function(callback) {
	// So few instructors that the query structure of this code literally does not matter
	Instructors.scan().loadAll().exec(callback);
}

// Make resources public
app.use(express.static('public'));

/*
 Routes
*/
// Get list of instructors
app.get('/instructors', function(req, res) {
	get_instructors(function(err, result) {
		if(err) {
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
	const name = req.body.name;
	const comment = req.body.comment;
	// Verify comment length
	if(comment.length < 15) {
		// TODO: Change appropriate error code
		res.status(500).send({error: 'Comment not long enough.'});
		return;
	}
	// Query the appropriate public key
	Instructors.get(name, function(err, instr){
		if (err) {
			console.log(err);
			res.status(500).send({error: 'Backend error #1'});
			return;
		}
		// Encode the comment with the given public key
		const public_key_string = instr.get('public_key');
		const buffer = Buffer.from(comment);
		const encrypted_comment = crypto.publicEncrypt(public_key_string, buffer).toString("base64");
		// Store the comment in the database
		Feedback.create({instructor: name, comment: encrypted_comment}, function(err, data){
			if(err) {
				console.log(err);
				res.status(500).send({error: 'Backend error #2'});
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
	const instructor = req.body.name;
	const private_key = req.body.private_key;
	
	// Query the feedback the TA has received
	Feedback.query(instructor).loadAll().exec(function(err, fb){
		if (err) {
			console.log(err);
			res.status(500).send({error: 'Backend error #3'});
			return;
		}
		res.status(200).send(fb.Items.map(item => {
			var buffer = Buffer.from(item.get('comment'), "base64");
			var decrypted = 'Provided key can\'t decrypt comment.';
			try {
				decrypted = crypto.privateDecrypt(private_key, buffer).toString("utf8");
			} catch (exception) {
				// Nothing to do here besides maybe logging it
			}
			return decrypted;
		}));
	});
});


// View page to generate new key pair for a given instructor, if instructor and current private key specified
app.get('/view_key', function(req, res){
	res.sendFile(path.join(__dirname + '/change_key.html'));
});

// Change current instructors public key if private key matches it
app.post('/change_key', function(req, res) {
	const instructor = req.body.name;
	const public_key = req.body.public_key;
	
	// Query relevant instructor
	Instructors.get(instructor, function(err, instr) {
		if (err) {
			res.status(500).send({error: 'Backend error #6'});
			return;
		}
		if(public_key != instr.get('public_key')) {
			res.status(403).send({error: 'Wrong key specified.'});
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
			// TODO: Query all feedbacks, decrypt them, encrypt them with new key, update.
			
			// Save new key
			console.log(error);
			Instructors.update({name: instructor, public_key: npublic}, function(err, result){
				if (err) {
					console.log(err);
					res.status(500).send({error: 'Backend error #7'});
					return;
				}
				res.status(200).send({publick: npublic, privatek: nprivate});
			});
		});
		
	});
});

app.listen(3000, function () {
  console.log("Server started.");
});