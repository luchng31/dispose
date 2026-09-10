<template>
  <span class="stt" :class="cls">{{ state }}</span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ state: string }>()

const cls = computed(() => {
  switch (props.state) {
    case '待分配':
      return 'stt-assign'
    case '待修复':
      return 'stt-fix'
    case '待复测':
      return 'stt-retest'
    case '已闭合':
      return 'stt-closed'
    case '已延期':
      return 'stt-delay'
    case '已忽略':
      return 'stt-ignore'
    default:
      return 'stt-assign'
  }
})
</script>

<style scoped>
.stt {
  display: inline-block;
  padding: 2px 10px;
  font-size: 12px;
  font-weight: 500;
  line-height: 20px;
  border-radius: 10px;
  white-space: nowrap;
}
.stt-assign {
  color: #5b6b7f;
  background: #f0f2f5;
}
.stt-fix {
  color: #d96c06;
  background: #fef3e6;
}
.stt-retest {
  color: #0082ef;
  background: #eaf4fe;
}
.stt-closed {
  color: #07c160;
  background: #e7f8ef;
}
.stt-delay {
  color: #fff;
  background: #e86a10;
}
.stt-ignore {
  color: #8a94a6;
  background: transparent;
  border: 1px solid #d5dae1;
  padding: 1px 9px;
}
</style>
