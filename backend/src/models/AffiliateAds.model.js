const {Schema,model} = require('mongoose');
const { time } = require('three/tsl');

const AffiliateAdsSchema = new Schema({
    name: {
        type : String,
        required: true,
    },
    discrption:{
        type:String,
        required:true,
    },
    price:{
        type:Number,
        required:true,
    },
    ImageUrl:{
        type:String,
        required:true,
    },
    AffiliateLink:{
        type:String,
        required:true,
    },
},{timestamps:true});

module.exports = model('AffiliateAds', AffiliateAdsSchema);