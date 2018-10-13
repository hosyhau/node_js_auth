var mongoose = require('mongoose');
var config = require('./config');
var connectDB = `mongodb://`+config.username+`:`+config.password+`@ds253871.mlab.com:53871/authenticatio`;
mongoose.connect(connectDB);
