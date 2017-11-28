var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var express = require('express');
var sessions = require("client-sessions");

var app = express();
app.use(express.static('./public'))

var sessionsMiddleware = sessions({
    cookieName: 'auth-cookie',  // front-end cookie name
    secret: 'DR@G0N$',        // the encryption password : keep this safe
    requestKey: 'session',    // we can access our sessions at req.session,
    duration: (86400 * 1000) * 7, // one week in milliseconds
    cookie: {
        ephemeral: false,     // when true, cookie expires when browser is closed
        httpOnly: true,       // when true, the cookie is not accesbile via front-end JavaScript
        secure: false         // when true, cookie will only be read when sent over HTTPS
    }
}) // encrypted cookies!
app.use(sessionsMiddleware)

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/** Database setup **/
mongoose.connect('mongodb://localhost/jail', function(err) {
    if( err ) {
        console.error('Could not connect to the Mongo Jailhouse!');
    } else {
        console.info("Connected to the Jailhouse!");
    }
});

var User = mongoose.model('user', mongoose.Schema({
    username : { type: String, required: true, unique: true },
    password : { type: String, required: true },
    role     : { type: String, required: true }
}));


// app.get('/example', protected, function(req, res){ res.send('example'); });


var permissionsToCafe = function(req, res, next){
  User.findById(req.session._id, function(err, user){
    if ( user.role === "guard" || user.role === "warden" || user.role === "prisoner") {
        //console.log("user is logged in. proceeding to next route handler")
        next()
    }
    else {
        console.log("forbidden")
        res.redirect('/register')
    }
  })
}

var permissionsToVisitorLounge = function(req, res, next){
  User.findById(req.session._id, function(err, user){
    if ( user.role === "guard" || user.role === "warden" || user.role === "visitor") {
        //console.log("user is logged in. proceeding to next route handler")
        next()
    }
    else {
        console.log("forbidden")
        res.redirect('/register')
    }
  })
}

var permissionsToLobby = function(req, res, next){
  User.findById(req.session._id, function(err, user){
    if ( user.role === "guard" || user.role === "warden" || user.role === "visitor") {
        //console.log("user is logged in. proceeding to next route handler")
        next()
    }
    else {
        console.log("forbidden")
        res.redirect('/register')
    }
  })
}

var permissionsToWardenOffice = function(req, res, next){
  User.findById(req.session._id, function(err, user){
    if ( user.role === "warden" ) {
        //console.log("user is logged in. proceeding to next route handler")
        next()
    }
    else {
        console.log("forbidden")
        res.redirect('/register')
    }
  })
}

var permissionsToMalloryCell = function(req, res, next){
  User.findById(req.session._id, function(err, user){
    if ( user.role === "warden" || user.username === "mallory" || user.role === 'guard') {
        //console.log("user is logged in. proceeding to next route handler")
        next()
    }
    else {
        console.log("forbidden")
        res.redirect('/register')
    }
  })
}

var permissionsToEveCell = function(req, res, next){
  User.findById(req.session._id, function(err, user){
    if ( user.username === "eve" || user.role === "warden" || user.role === 'guard') {
        //console.log("user is logged in. proceeding to next route handler")
        next()
    }
    else {
        console.log("forbidden")
        res.redirect('/register')
    }
  })
}



app.get('/', function(req, res){
    res.sendFile('./html/login.html', {root:'./public'});
});
app.get('/jail', function(req, res, next){
    res.sendFile('./html/jail.html', {root:'./public'});
});
app.get('/lobby', permissionsToLobby, function(req, res, next){
    res.sendFile('./html/lobby.html', {root:'./public'});
});
app.get('/visitors-lounge', permissionsToVisitorLounge, function(req, res, next){
    res.sendFile('./html/visitors-lounge.html', {root:'./public'});
});
app.get('/cafeteria', permissionsToCafe, function(req, res){
          res.sendFile('./html/cafeteria.html', {root:'./public'});
    })
app.get('/wardens-office', permissionsToWardenOffice, function(req, res, next){
    res.sendFile('./html/wardens-office.html', {root:'./public'});
});
app.get('/cell-m', permissionsToMalloryCell, function(req, res, next){
    res.sendFile('./html/cell-m.html', {root:'./public'});
});
app.get('/cell-e', permissionsToEveCell, function(req, res, next){
    res.sendFile('./html/cell-e.html', {root:'./public'});
});








app.get('/me', function(req, res){
    User.findOne({_id: req.session.uid}, function(err, user){
        res.send(user)
    })
})

app.post('/login', function(req, res) { // form post submission
    console.info('auth.login.payload:', req.body);

    User.findOne({ username: req.body.username }, function(err, user) {
        if( err) {
            console.log('MongoDB error:', err);
            res.status(500).send("failed to find user")
        }
        else if( !user ) {
            console.log('No user found!');
            res.status(403).send("<h1>Login failed</h1>");
        } else {
            console.log('auth.login.user', user);
            // at this point, user.password is hashed!
            bcrypt.compare(req.body.password, user.password, function(bcryptErr, matched) {
                // matched will be === true || false
                if( bcryptErr ) {
                    console.error('MongoDB error:', bcryptErr);
                    res.status(500).send("mongodb error");
                } else if ( !matched ) {
                    // forbidden, bad password
                    console.warn('Password did not match!');
                    res.status(403).send("failed to log in");
                } else {
                    req.session._id = user._id; // this is what keeps our user session on the backend!
                    res.send({ success: 'Login success' }); // send a success message
                }
            });
        }
    });
});



app.listen(8080)
