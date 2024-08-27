const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const database = require('./src/services/database');
const LocalStrategy = require('passport-local').Strategy;
require('dotenv').config();

const app = express();

app.use(passport.initialize());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'src', 'views'));
app.set('view engine', 'ejs');

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await database.getUserByName(username);
      if (!user) {
        return done(null, false, { message: 'Incorrect username or password' });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return done(null, false, { message: 'Incorrect username or password' });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await database.getUserById(user.id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});


// routes for crud operations on posts.

app.get('/api/posts/:postid', verifyToken, async (req, res) => {
    const postId = parseInt(req.params.postid);
    try {
    const post = await database.getPostById(postId);
    console.log(post);
    res.json({ post: post });
    } catch (error) {
      console.error('Error fetching post from server: ',error);
      return res.status(500).json({error:'Error fetching post.'});
    }
});

app.post('/api/posts', verifyToken, verifyAdmin, async (req, res) => {
    try {
       const post = await database.createPost(req.body.title, req.body.text, req.token.id);
       
       res.json({ message: 'Post inserted correctly in database'});       
    } catch (error) {
        console.error('Error creating post', error);
        return res.status(500).json({error:'Error creating post.'});
    }
  
});

app.patch('/api/posts/:postid', verifyToken, verifyAdmin, async (req, res) => {
    const postId = parseInt(req.params.postid);
    const updateData = parseEditPostBody(req.body);
  try {
    const updatedPost = await database.updatePost(postId, updateData);
    res.json( {message: 'Post updated successfully'});
    
  } catch (error) {
    console.error('Error updating post: ', error);
    return res.status(500).json({error:'Error updating post.'})
  }
})

app.delete('/api/posts/:postid', verifyToken, verifyAdmin, async (req, res) => {
  const postId = parseInt(req.params.postid);
  try {
    const post = await database.deletePostById(postId);
    res.json( { message: 'Post deleted correctly from database.'})
  } catch (error) {
    console.error('Error deleting post from database: ',error);
    return res.status(500).json({error:'Error deleting post.'});
  }
});


app.post('/api/posts/:postid/comments', verifyToken, async (req, res) => {
  const postId = parseInt(req.params.postid);
  const userId = req.token.id;
  try {
    const comment = await database.createComment(userId, req.body.text, postId);
    res.json( { message: 'Comment created successfully', comment: comment});
  } catch (error) {
    console.error('Error creating comment',error);
    return res.status(500).json({error:'Error creating comment'});
  }
});


app.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(401).json({ message: info.message });
    }
    const token = jwt.sign(
      { id: user.id, username: user.username, type: user.type },
      process.env.JWT_SECRET,
      { expiresIn: '7 days' }
    );
    return res.json({ token: token });
  })(req,res,next);
});

app.get('/register', (req, res) => {
  res.render('index');
});

app.post('/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await database.createUser(req.body, hashedPassword);
    res.redirect('/register');
  } catch (error) {
    console.error('Error creating account', error);
    return res.status(500).json({errorMsg:'Error creating account.', error});
  }
});



// middlewares for authorization. might move to another module?


function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader === 'undefined') {
    return res.sendStatus(403);
  }
  const bearer = bearerHeader.split(' ');
  const bearerToken = bearer[1];

  jwt.verify(bearerToken, process.env.JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return res.status(403);
    }

  req.token = decodedToken;
  next();
});
}

function verifyAdmin(req, res, next) {
    if (req.token.type !== "Admin") {
        return res.sendStatus(403);
    }
    next();
}

// Utility function 

function parseEditPostBody(formBody) {
  const updateData = {};
    if (formBody.title) {
      updateData.title = formBody.title;
    }
    if (formBody.text) {
      updateData.text = formBody.text;
    }
    if (formBody.isPublished) {
      const isPub = formBody.isPublished == 'true' ? true : false;
      updateData.isPublished = isPub;
      updateData.createdAt = new Date();
    }

    return updateData;
}

app.listen(3000, () => console.log('Server listening on port 3000'));
