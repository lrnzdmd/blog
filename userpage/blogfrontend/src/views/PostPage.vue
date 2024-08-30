<script setup>
    import CommentCard from '@/components/CommentCard.vue';
import formatDate from '@/utils/formatDate';
import LoadingSpinner from '@/components/icons/LoadingSpinner.vue';
    import axios from 'axios';
    import { isLoggedIn } from '@/utils/useAuth';
    import { onMounted, ref } from 'vue';

    const props = defineProps({
        postId: Number,
    });


    const posts = ref([]);
    const index = ref('');
    const loading = ref(true);
    const error = ref(null);
    const commentText = ref('');
    const errorMsg = ref('');

    async function getPostList(){
        const response = await axios.get('https://deliberate-collie-birdiepoop-197e5571.koyeb.app/api/posts');
        return response.data.posts
    }

    async function handleSubmit() {
        try {
        const response = await axios.post(`https://deliberate-collie-birdiepoop-197e5571.koyeb.app/api/comments/new/${props.postId}`, {
            text:commentText.value,
        }, {
            headers: { Authorization: `Bearer ${localStorage.getItem('jwtToken')}`},
        }
    );
        if (response.status === 200) {
            console.log(response)
            posts.value = await getPostList();
            index.value = posts.value.findIndex(post => post.id === props.postId); 
        }
    } catch (error) {
        console.error('Error posting comment', error);
        errorMsg.value = 'Failed to post comment'
    }
}
    onMounted(async () => {
        try {
          posts.value = await getPostList();
          index.value = posts.value.findIndex(post => post.id === props.postId);  
        } catch (error) {
            error.value = 'Cannot load the post, please try later.'
        } finally {
            loading.value = false;
        }
        
        
        
    })


</script>

<template>
    <div class="flex justify-center">
        <div v-if="loading" class="w-3/4 px-8 py-12 bg-white">
            <LoadingSpinner></LoadingSpinner>
        </div>
        <div v-else-if="error" class="w-3/4 px-8 py-12 bg-white">
            {{ error }}
        </div>
        <div v-else class="w-3/4 px-8 py-12 bg-white ">
            <div class="flex items-center justify-between">
                <span class="text-lg font-light text-gray-600 dark:text-gray-400">{{
                    formatDate(posts[index].createdAt)}}</span>
            </div>

            <div class="mt-2">
                <h2 class="text-3xl font-bold text-gray-700" tabindex="0" role="link">{{ posts[index].title }}</h2>
                <p class="text-lg mt-2 text-gray-600 ">{{ posts[index].text }}</p>
            </div>

            <div class="flex items-center justify-between mt-4">
                <div class="flex items-center">
                    <p class="text-lg font-bold text-gray-700 cursor-pointer " tabindex="0" role="link">
                        {{ posts[index].author.username }}</p>
                </div>
                <a v-if="posts[index + 1]" :href="`/posts/${posts[index + 1].id}`" class="text-blue-600 hover:underline"
                    tabindex="0" role="link">Older posts</a>
            </div>
        </div>
    </div>

    <div class="bg-black w-5/6  self-center mx-auto" style="height: 1px;"></div>

    <div class="flex justify-center mt-8">
        <p v-if="errorMsg" class="text-lg text-red-500">{{ errorMsg }}</p>
        <div v-if="posts.length > 0" class="w-3/4">
            <h3 class="self-start px-8 text-2xl font-bold text-gray-700">Comments</h3>
            <div class="px-8 py-8" v-for="comment in posts[index].comments" :key="comment.id">
                <CommentCard :username="comment.commenter.username" :text="comment.text"
                    :created-at="formatDate(comment.createdAt)"></CommentCard>
            </div>
            <div class="bg-black w-full  self-center mx-auto" style="height: 1px;"></div>
            
                <form @submit.prevent v-if="isLoggedIn" class="flex flex-col w-full px-8 mt-4" action="" method="post">
        <textarea v-model="commentText" class="w-full py-3 mt-2 text-gray-700 bg-white border rounded-lg px-4  focus:border-sky-400  focus:ring-sky-300 focus:outline-none focus:ring focus:ring-opacity-40" required name="message" id="message" placeholder='New comment...'></textarea>
        <button @click="handleSubmit" class="w-1/5 self-end mt-2 px-6 py-3 text-md font-semibold text-white tracking-wide capitalize transition-colors duration-300 transform bg-sky-600  shadow-gray-950 rounded-lg hover:bg-sky-500 focus:outline-none focus:ring focus:ring-sky-300 focus:ring-opacity-50" type="submit">Submit</button>
    </form>



        </div>
    </div>


</template>