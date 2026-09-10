<template>
  <span class="sev" :class="cls">{{ severity }}</span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ severity: string }>()

const cls = computed(() => {
  if (['critical', '严重', '超高'].includes(props.severity) || props.severity?.toLowerCase() === 'critical')
    return 'sev-crit'
  if (['high', '高危', '高'].includes(props.severity) || props.severity?.toLowerCase() === 'high')
    return 'sev-high'
  if (['medium', '中危', '中'].includes(props.severity) || props.severity?.toLowerCase() === 'medium')
    return 'sev-mid'
  return 'sev-low'
})
</script>

<style scoped>
.sev {
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
}
.sev-crit {
  color: #fa5151;
}
.sev-high {
  color: #d96c06;
}
.sev-mid {
  color: #d19a00;
}
.sev-low {
  color: #8a94a6;
}
</style>
