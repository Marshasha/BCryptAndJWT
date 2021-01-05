const fs = require('fs');
const path = require('path');
const JwtStrategy = require('passport-local').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt;
const User = require('mongoose').model('User');


const pathToKey = path.join(__dirname, '..', 'id_rsa_pub.pem');
const PUB_KEY = fs.readFileSync(pathToKey, 'utf8');

const options = {   
    jwtFromRequest : ExtractJwt.fromAuthHeaderAsBearerToken(),
    secret : PUB_KEY,
    algorithms : ['RS256']
};

const strategy = new JwtStrategy(options, (payload, done)=>{

    User.findOne({_id: payload.sub})
    .then((user)=>{
            if(user){
                return done(null, user);
            }else{
                return done(null, false);
            }
    })
    .catch(err => done(err, null));
});

module.exports = (passport) =>{
    passport.use(strategy);
}