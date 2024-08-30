<script setup>
import { login } from '@/utils/useAuth';
import axios from 'axios';
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import SiteLogo from '@/components/icons/SiteLogo.vue';
import IconUser from '@/components/icons/IconUser.vue';
import IconPassword from '@/components/icons/IconPassword.vue';

const username = ref('');
const password = ref('');
const errorMsg = ref('');
const router = useRouter();

async function handleSubmit() {
    try {
        const response = await axios.post('https://deliberate-collie-birdiepoop-197e5571.koyeb.app/login', {
            username:username.value,
            password:password.value,
        });
        if (response.status === 200) {
            login(response.data.token);
            router.push('/');
        }
    } catch (error) {
        console.error('Error during login', error);
        errorMsg.value = 'Login failed. Invalid credentials.'
    }
}

</script>

<template>

    <section class="bg-gray-50">
        <div class="container flex items-center justify-center min-h-screen px-6 mx-auto">
            <form @submit.prevent="handleSubmit" class="w-full max-w-md">
                <SiteLogo :size="8"></SiteLogo>
                <h1 class="mt-3 text-2xl font-semibold text-gray-800 capitalize sm:text-3xl">Log In</h1>
                <p v-if="errorMsg" class="text-red-500 mt-2">{{ errorMsg }}</p>
                <div class="relative flex items-center mt-6">
                    <IconUser></IconUser>

                    <input type="text" name="username" v-model="username"
                        class="block w-full py-3 text-gray-700 bg-white border rounded-lg px-11 focus:border-blue-400  focus:ring-blue-300 focus:outline-none focus:ring focus:ring-opacity-40"
                        placeholder="Username" required>
                </div>

                <div class="relative flex items-center mt-4">
                    <IconPassword></IconPassword>

                    <input type="password" name="password" v-model="password"
                        class="block w-full px-10 py-3 text-gray-700 bg-white border rounded-lg  focus:border-blue-400  focus:ring-blue-300 focus:outline-none focus:ring focus:ring-opacity-40"
                        placeholder="Password" required>
                </div>

                <div class="mt-6">
                    <button
                        class="w-full px-6 py-3 text-sm font-medium tracking-wide text-white capitalize transition-colors duration-300 transform bg-blue-500 rounded-lg hover:bg-blue-400 focus:outline-none focus:ring focus:ring-blue-300 focus:ring-opacity-50">
                        Sign in
                    </button>



                    <div class="mt-6 text-center ">
                        <RouterLink to="/login" class="text-sm text-blue-500 hover:underline dark:text-blue-400">
                            Already have an account? Log in
                        </RouterLink>
                    </div>
                </div>
            </form>
        </div>
    </section>


</template>