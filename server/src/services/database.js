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

async function createPost(title, text, authorId) {
    try {
        const post = await prisma.post.create({
            data: {
                title: title,
                text: text,
                authorId: authorId,
            },
        });
        return post;
    } catch (error) {
        console.error('Error creating post: ', error);
        throw error;
    }
}


module.exports = { getUserByName, getUserById, createUser, createPost };