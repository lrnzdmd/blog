<script setup>
defineProps({

  id: {
    type: Number,
    required:true
  },

  title: {
    type: String,
    required: true
  },
  text: {
    type: String,
    required: true
  },
  author: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    required: true
  }
})
</script>

<template>
 <div>
                <div class="mt-2">
                    <span class="text-sky-500 uppercase tracking-wider">Article</span>

                    <h1 class="mt-4 text-xl font-semibold text-gray-800  truncate">
                        {{title}}
                    </h1>

                    <p class="mt-2 text-gray-500 dark:text-gray-400 truncate">
                        {{text}}
                    </p>

                    <div class="flex items-center justify-between mt-4">
                        <div>
                            <a href="#" class="text-lg font-medium text-gray-700 dark:text-gray-300 hover:underline hover:text-gray-500">
                                {{author}}
                            </a>

                            <p class="text-sm text-gray-500 dark:text-gray-400">{{createdAt}}</p>
                        </div>

                        <RouterLink :to="`/posts/${id}`" class="inline-block text-sky-500 underline hover:text-sky-400">Read more</RouterLink>
                    </div>

                </div>
            </div>
</template>

