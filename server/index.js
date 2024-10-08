const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const database = require('./src/services/database');
const LocalStrategy = require('passport-local').Strategy;
const Joi = require('joi');
require('dotenv').config();

const app = express();

app.use(passport.initialize());
app.use(cors());
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

app.get(('/api/posts/', verifyToken, async (req, res) => {
  try {
    const posts = await database.getAllPosts();
    res.json({posts});
  } catch (error) {
    console.error('Error fetching posts list');
    res.status(500).json({error:'Error fetching posts list'});
  }
}));

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

app.post('/api/posts', verifyToken, verifyAdmin, validatePost, async (req, res) => {
    try {
       const post = await database.createPost(req.body.title, req.body.text, req.token.id);
       
       res.json({ message: 'Post inserted correctly in database'});       
    } catch (error) {
        console.error('Error creating post', error);
        return res.status(500).json({error:'Error creating post.'});
    }
  
});

app.patch('/api/posts/:postid', verifyToken, verifyAdmin, validateUpdatePost, async (req, res) => {
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


// routes for crud operations on comments


app.get('/api/comments', verifyToken, async (req, res) => {
    try {
      const allComments = await database.getAllComments();
      res.json({allComments});
    } catch (error) {
      console.error('Error fetching comments list', error);
      return res.status(500),json({error:'Error fetching comments'});
    }
});

app.get('/api/posts/:postid/comments', verifyToken, async (req, res) => {
  const postId = parseInt(req.params.postid);
  try {
    const comments = await database.getAllCommentsOfPost(postId);
    res.json({comments});
  } catch (error) {
    console.error('Error fetching comments list');
    return res.status(500).json({error:'Error fetching comments'});
  }
});



app.post('/api/comments', verifyToken, validateComment, async (req, res) => {
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

app.patch('/api/comments/:commentid', verifyToken, verifyAdmin, validateUpdateComment, async (req, res) => {
  const commentId = parseInt(req.params.commentid);
  try {
    const updatedComment = await database.updateComment(commentId, req.body.text);
    res.json({ message: 'Comment update successfully', comment:updatedComment});
  } catch (error) {
    console.error('Error updating comment',error);
    return res.status(500).json({error:'Error updating comment'});
  }
})

app.delete('/api/comments/:commentid', verifyToken, verifyAdmin, async (req, res) => {
  const commentId = parseInt(req.params.commentid);
  try {
    const comment = await database.deleteCommentById(commentId);
    res.json({message: 'Comment deleted successfully', comment});
  } catch (error) {
    console.error('Error deleting comment', error);
    return res.status(500).json({error:'Error deleting comment'});
  }
});

app.post('/login', validateLogin, (req, res, next) => {
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

app.post('/register', validateRegistration, async (req, res) => { 
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

// Validation middlewares

const validateRegistration = (req, res, next) => {
  const { error } = registrationSchema.validate(req.body);
  if (error) {
      return res.status(400).json({ error: error.details[0].message });
  }
  next();
};

const validateLogin = (req, res, next) => {
  const { error } = loginSchema.validate(req.body);
  if (error) {
      return res.status(400).json({ error: error.details[0].message });
  }
  next();
};

const validatePost = (req, res, next) => {
  const { error } = postSchema.validate(req.body);
  if (error) {
      return res.status(400).json({ error: error.details[0].message });
  }
  next();
};

const validateUpdatePost = (req, res, next) => {
  const { error } = updatePostSchema.validate(req.body);
  if (error) {
      return res.status(400).json({ error: error.details[0].message });
  }
  next();
};

const validateComment = (req, res, next) => {
  const { error } = commentSchema.validate(req.body);
  if (error) {
      return res.status(400).json({ error: error.details[0].message });
  }
  next();
};

const validateUpdateComment = (req, res, next) => {
  const { error } = updateCommentSchema.validate(req.body);
  if (error) {
      return res.status(400).json({ error: error.details[0].message });
  }
  next();
};

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

// Joi validation schemas for post and patch routes

const registrationSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  password: Joi.string().min(6).required(),
  eMail: Joi.string().email().required()
});

const loginSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  password: Joi.string().min(6).required()
});

const postSchema = Joi.object({
  title: Joi.string().min(3).max(100).required(),
  text: Joi.string().min(3).required(),
  isPublished: Joi.boolean().optional()
});

const updatePostSchema = Joi.object({
  title: Joi.string().min(3).max(100).optional(),
  text: Joi.string().min(3).optional(),
  isPublished: Joi.boolean().optional()
});

const commentSchema = Joi.object({
  text: Joi.string().min(1).max(2500).required(),
  parentId: Joi.number().integer().required()
});

const updateCommentSchema = Joi.object({
  text: Joi.string().min(1).max(2500).required()
});

app.listen(3000, () => console.log('Server listening on port 3000'));
