<script setup>
import ArticlePreview from '../components/ArticlePreview.vue';
import SectionTitle from '../components/SectionTitle.vue';
import MailingList from '../components/MailingList.vue';
import axios from 'axios';
import { onMounted, ref } from 'vue';

const articles = ref({
    latest: [],
    popular: []
});

async function fetchLatestArticles(){
    try {
        const response = await axios.get('https://deliberate-collie-birdiepoop-197e5571.koyeb.app/api/posts/list/latest'); // to add api url link
        articles.value.latest = response.data.posts;
    } catch (error) {
        console.error('Error fetching latest articles', error);
    }
}

async function fetchPopularArticles(){
    try {
        const response = await axios.get('https://deliberate-collie-birdiepoop-197e5571.koyeb.app/api/posts/list/popular'); // to add api url link
        articles.value.popular = response.data.posts;
    } catch (error) {
        console.error('Error fetching latest articles', error);
    }
}
onMounted(async () => {
    await fetchLatestArticles();
    await fetchPopularArticles();
})

</script>

<template>
    <header class=" h-[28rem] bg-gray-50">
        <div class=" container mx-auto px-4 flex h-full py-6 items-center">
            <div class=" max-w-xl">
                <p class=" text-sky-500 uppercase tracking-wider">bird wisdom</p>
                <h2 class=" text-3xl xl:text-4xl font-bold mt-4 text-gray-800 capitalize">Here to fulfill your daily
                    bird news needs</h2>
                <p class=" text-gray-500 mt-4 text-lg">Lorem ipsum dolor sit amet consectetur adipisicing elit. Soluta
                    error odit vel minima optio consequuntur atque omnis, repellendus eos, rerum totam quas vitae
                    voluptatibus, facere distinctio fugit? Nam, iure expedita!</p>
            </div>
        </div>
    </header>
    <section class=" container mx-auto px-4 py-16">
        <SectionTitle>Latest Articles</SectionTitle>
        <div class="grid grid-cols-1 gap-8 md:grid-cols-2 mt-6 xl:grid-cols-3">
            <ArticlePreview v-for="article in articles.latest" :key="article.id" :id="article.id" :title="article.title" :text="article.text" :author="article.author.username"
                :created-at="new Date()"></ArticlePreview>
        </div>
    </section>
    <MailingList></MailingList>
    <section class=" container mx-auto px-4 py-10 lg:py-16">
        <SectionTitle>Most Popular</SectionTitle>
        <div class="grid grid-cols-1 gap-8 md:grid-cols-2 mt-6 xl:grid-cols-3">
            <ArticlePreview v-for="article in articles.popular" :key="article.id" :id="article.id" :title="article.title" :text="article.text" :author="article.author.username"
            :created-at="new Date()"></ArticlePreview>
        </div>
    </section>
</template>