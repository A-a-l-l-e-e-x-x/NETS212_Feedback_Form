# NETS 212 TA Feedback Form
## What?
Small node application for students of Scalable & Cloud Computing to provide feedbacks to the Teaching Assistants of the class.
The feedback is completely anonymous and encrypted, such that only the designated TA is able to decrypt and see it.

## Why?
Would have had to create *multiple* Google Forms to achieve the same effect, and it could potentially have spammed emails.
Instead, this groups everything in one place. It uses only concepts taught in the class, to showcase their practicality, even though the app itself is very small.


## How? 
Uses Node, express, DynamoDB, EC2 (Well, any server really), jQuery, Bootstrap.
Code should look similar to the homeworks of the course.
It is quick & dirty code so don't take anything away in terms of design, but feel free to browse around - it's basically all in one file.

## For TAs:
### Generating access keys
Navigate to the key generation page (`/view_key`), specify who you are and enter the default private key provided to you, and generate a new key pair.

Save the generated key pair -- well, especially the private key. You'll need it to change your key in the future, or access your feedback.
Any feedback written with a key that you've lost will be lost, unless you've generated a new key yourself in between.

### Viewing feedback

Provide your current private key pair and who you are, then click on Submit to view feedback written for you.
Only you are able to view this feedback.

# [Current IP Address](http://ec2-3-91-182-224.compute-1.amazonaws.com:3000/)
