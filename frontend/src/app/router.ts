import { createRouter, createWebHashHistory } from 'vue-router'
import HomePage from '../pages/home/HomePage.vue'

// hash-адреса (#/...) — в Wails нет сервера, который отдал бы index.html на любой путь.
export const router = createRouter({
  history: createWebHashHistory(),
  routes: [{ path: '/', name: 'home', component: HomePage }],
})
