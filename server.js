var express = require('express');
var session = require('express-session');
var passport = require('passport');
var FacebookStrategy = require('passport-facebook').Strategy;


var port = 8889;
var app = express();

app.use(session({secret: 'simulation_theory'}));
app.use(passport.initialize());
app.use(passport.session());



passport.use(new FacebookStrategy({
  clientID: '1607402999483294',
  clientSecret: 'aa5fe9b14407437d4e0500ea30e9d422',
  callbackURL: 'http://localhost:8889/auth/facebook/callback'
}, function(token, refreshToken, profile, done) {
  return done(null, profile);
}));

app.get('/auth/facebook', passport.authenticate('facebook'));
app.get('/auth/facebook/callback', passport.authenticate('facebook', {
	successRedirect: '/me',
	failureRedirect: '/failure'
}));

passport.serializeUser(function(user, done){
	done(null, user);
})
passport.deserializeUser(function(obj, done){
	done(null, obj);
})

var isAuthed = function(req, res, next){
	if(!req.isAuthenticated()){
		res.redirect('failure');
	} else {
		next();
	}
}

app.get('/me', function(req, res){
	return res.json(req.user);
})

app.listen(port);

