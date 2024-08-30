import { ref } from 'vue';

const isLoggedIn = ref(localStorage.getItem('jwtToken') ? true : false);


    function login(token) {
        localStorage.setItem('jwtToken', token);
        isLoggedIn.value = true;
    }

    function logout() {
        localStorage.removeItem('jwtToken');
        isLoggedIn.value = false;
    }

    export {
        isLoggedIn,
        login,
        logout
    };
