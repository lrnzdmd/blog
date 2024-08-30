<script setup>
import IconEmail from '@/components/icons/IconEmail.vue';
import IconPassword from '@/components/icons/IconPassword.vue';
import IconUser from '@/components/icons/IconUser.vue';
import SiteLogo from '@/components/icons/SiteLogo.vue';
import axios from 'axios';
import { ref } from 'vue';
import { useRouter } from 'vue-router';

const username = ref('');
const password = ref('');
const confirmPassword = ref('');
const errorMsg = ref('');
const successMsg = ref('');
const eMail = ref('');
const router = useRouter();

async function handleSubmit() {
    try {
        const response = await axios.post('https://deliberate-collie-birdiepoop-197e5571.koyeb.app/register', {
            username:username.value,
            password:password.value,
            eMail:eMail.value,
        });
        if (response.status === 200) {
            successMsg.value = 'Registration successful, redirecting to login...';
            setTimeout(() => router.push('/login'),4000);
        }
    } catch (error) {
        console.error('Error during registration', error);
        errorMsg.value = 'Registration failed, try other credentials.'
    }
}

</script>

<template>

    <section class="bg-gray-50">
        <div class="container flex items-center justify-center min-h-screen px-6 mx-auto">
            <form @submit.prevent="handleSubmit" class="w-full max-w-md">
                <SiteLogo :size="8"></SiteLogo>
                <h1 class="mt-3 text-2xl font-semibold text-gray-800 capitalize sm:text-3xl">Register</h1>
                <p v-if="errorMsg" class="text-red-500 mt-2">{{ errorMsg }}</p>
                <p v-if="successMsg" class="text-emerald-500 mt-2">{{ successMsg }}</p>
                <div class="relative flex items-center mt-6">
                    <IconUser></IconUser>

                    <input type="text" name="username" v-model="username"
                        class="block w-full py-3 text-gray-700 bg-white border rounded-lg px-11 focus:border-blue-400  focus:ring-blue-300 focus:outline-none focus:ring focus:ring-opacity-40"
                        placeholder="Username" required>
                </div>

                <div class="relative flex items-center mt-4">
                <IconEmail></IconEmail>

                <input type="email" name="eMail" v-model="eMail" class="block w-full py-3 text-gray-700 bg-white border rounded-lg px-11  focus:border-blue-400  focus:ring-blue-300 focus:outline-none focus:ring focus:ring-opacity-40" placeholder="Email address" required>
            </div>

                <div class="relative flex items-center mt-4">
                    <IconPassword></IconPassword>

                    <input type="password" name="password" v-model="password"
                        class="block w-full px-10 py-3 text-gray-700 bg-white border rounded-lg  focus:border-blue-400  focus:ring-blue-300 focus:outline-none focus:ring focus:ring-opacity-40"
                        placeholder="Password" required>
                </div>

                <div class="relative flex items-center mt-4">
                    <IconPassword></IconPassword>

                    <input type="password" name="confirmPassword" v-model="confirmPassword"
                        class="block w-full px-10 py-3 text-gray-700 bg-white border rounded-lg  focus:border-blue-400  focus:ring-blue-300 focus:outline-none focus:ring focus:ring-opacity-40"
                        placeholder="Confirm Password" required>
                </div>

                <div class="mt-6">
                    <button
                        class="w-full px-6 py-3 text-sm font-medium tracking-wide text-white capitalize transition-colors duration-300 transform bg-blue-500 rounded-lg hover:bg-blue-400 focus:outline-none focus:ring focus:ring-blue-300 focus:ring-opacity-50">
                        Register
                    </button>



                    <div class="mt-6 text-center ">
                        <RouterLink to="/register" class="text-sm text-blue-500 hover:underline dark:text-blue-400">
                            Don’t have an account yet? Sign up
                        </RouterLink>
                    </div>
                </div>
            </form>
        </div>
    </section>


</template>