<template>
  <span class="sla" :class="cls">{{ label }}</span>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { slaCountdown } from '../utils/tickets'

const props = defineProps<{ slaDueAt?: string | null }>()

const info = computed(() => slaCountdown(props.slaDueAt))
const label = computed(() => info.value.label)
const cls = computed(() => {
  if (info.value.overdue) return 'sla-over'
  if (info.value.daysLeft === null) return 'sla-none'
  return 'sla-ok'
})
</script>

<style scoped>
.sla {
  font-size: 13px;
  white-space: nowrap;
}
.sla-ok {
  color: #5b6b7f;
}
.sla-none {
  color: #b0b8c5;
}
.sla-over {
  color: #fa5151;
  font-weight: 700;
}
</style>
