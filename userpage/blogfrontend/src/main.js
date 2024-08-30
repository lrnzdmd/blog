import './assets/style.css'
import { createApp } from 'vue'
import { createWebHistory, createRouter } from 'vue-router'
import App from './App.vue'
import HomePage from './views/HomePage.vue'
import LoginPage from './views/LoginPage.vue'
import RegisterPage from './views/RegisterPage.vue'
import PostPage from './views/PostPage.vue'


const app = createApp(App)

const routes = [
    {path: '/', component: HomePage},
    {path: '/login', component: LoginPage},
    {path: '/register', component: RegisterPage},
    {path: '/posts/:postid', component: PostPage, props: route => ({ postId: Number(route.params.postid) })}
];

const router = createRouter({
    history: createWebHistory(),
    routes,
});

app.use(router)


app.mount('#app')
