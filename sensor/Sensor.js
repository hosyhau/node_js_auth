var mongoose = require('mongoose');

var Schema = mongoose.Schema;

var SensorSchema = new Schema({
    name:String,
    value:{
        analog_value:Number,
        sensor_value:String,
        pinmode_value:String
    },
    average_value:String,
    sensor_type:String,
    staus:Boolean,
    process_time:Date
});
var sensors= mongoose.model('Sensor',SensorSchema);
module.exports= sensors;