const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function getUserByName(username) {
    try {
        const user = await prisma.user.findUnique({
            where: {username: username},
        });
        return user;
    } catch (error) {
        console.error(`Error fetching username '${username}' from database: `, error);
        throw error;
    }
}

async function getUserById(userId) {
    try {
        const user = await prisma.user.findUnique({
            where: {id: userId},
        });
        return user;
    } catch (error) {
        console.error(`Error fetching username '${userId}' from database: `, error);
        throw error;
    }
}

async function createUser(formBody, hashedPassword) {
    try {
       const user = await prisma.user.create({
        data: {
            username: formBody.username,
            password: hashedPassword,
            eMail: formBody.eMail,
        },
    });
    console.log('User created successfully:',user);
    return user;
    } catch (error) {
        console.error('Error creating user',error);
        throw error;
    }
    
}

async function getPostById(postId) {
    try {
        const post = await prisma.post.findUnique({
            where: {id: postId},
        });
        return post;
    } catch (error) {
        console.error(`Error fetching post id:'${postId}' from database: `, error);
        throw error;
    }
}

async function createPost(title, text, authorId) {
    try {
        const post = await prisma.post.create({
            data: {
                title: title,
                text: text,
                authorId: authorId,
            },
        });
        console.log('Post inserted correctly in database: ',post);
        return post;
    } catch (error) {
        console.error('Error creating post: ', error);
        throw error;
    }
}

async function updatePost(postId, data) {
    try {
        const post = await prisma.post.update({
            where: {id: postId},
            data: data,
        });
        console.log('Post successfully updated: ',post);
        return post;
    } catch {
        console.error('Error updating post: ',error);
        throw error;
    }
}

async function deletePostById(postId) {
    try {
        const post = await prisma.post.delete({
            where:{
                id:postId
            }});
            console.log('Post deleted correctly from database: ',post);
            return post; 
    } catch (error) {
        console.error('Error deleting post: ', error);
        throw error;
    }

}

async function createComment(commenterId, text, parentId) {
    try {
        const comment = await prisma.comment.create({
            data: {
                text: text,
                commenterId: commenterId,
                parentId: parentId,
            },
        });
        console.log('Comment added successfully', comment);
        return comment;
    } catch (error) {
        console.error('Error creating comment',error);
        throw error;
    }
}


module.exports = { getUserByName, getUserById, createUser, getPostById, createPost, updatePost, deletePostById, createComment };