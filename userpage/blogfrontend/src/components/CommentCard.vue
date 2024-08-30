<script setup>
defineProps({
    username: String,
    text: String,
    createdAt: String,
})
</script>

<template>
    <div class="flex items-center">
                    <p class="text-lg font-bold text-gray-700 cursor-pointer " tabindex="0" role="link">
                        {{ username }}</p>
                </div>

            <div class="mt-2">
                <p class="text-lg mt-2 text-gray-600 ">{{ text }}</p>
            </div>

            <div class="flex items-center justify-between">
                <span
                    class="text-md font-light text-gray-600 dark:text-gray-400">{{ createdAt }}</span>
            </div>
</template>