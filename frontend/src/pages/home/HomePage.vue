<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { getVersion } from '../../shared/api/version'

const version = ref('…')
const error = ref('')

onMounted(async () => {
  try {
    version.value = await getVersion()
  } catch (e) {
    error.value = String(e)
  }
})
</script>

<template>
  <main class="home">
    <h1>Brassbox</h1>
    <p v-if="error" class="error">Нет связи с Go: {{ error }}</p>
    <p v-else data-test="version">v{{ version }}</p>
  </main>
</template>

<style scoped>
.home {
  padding: 32px;
}
.error {
  color: #f66;
}
</style>
