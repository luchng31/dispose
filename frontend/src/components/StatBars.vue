<template>
  <div class="stat-bars">
    <div v-for="item in items" :key="item.label" class="bar-row">
      <span class="bar-label">{{ item.label }}</span>
      <div class="bar-track">
        <div class="bar-fill" :class="item.tone ?? 'default'" :style="{ width: pct(item.value) }" />
      </div>
      <span class="bar-value">{{ item.value }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
export interface StatBarItem {
  label: string
  value: number
  tone?: 'danger' | 'warning' | 'success' | 'info' | 'default'
}

const props = withDefaults(defineProps<{ items: StatBarItem[]; max?: number }>(), { max: 0 })

function pct(v: number): string {
  const peak = props.max > 0 ? props.max : Math.max(0, ...props.items.map((i) => i.value))
  if (peak <= 0) return '0%'
  return `${Math.round((v / peak) * 100)}%`
}
</script>

<style scoped>
.stat-bars {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.bar-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.bar-label {
  width: 110px;
  flex: none;
  color: #8a94a6;
  font-size: 13px;
  text-align: right;
}
.bar-track {
  flex: 1;
  height: 14px;
  background: #f2f3f5;
  border-radius: 7px;
  overflow: hidden;
}
.bar-fill {
  height: 100%;
  border-radius: 7px;
  background: #0082ef;
}
.bar-fill.danger {
  background: #fa5151;
}
.bar-fill.warning {
  background: #fa9d3b;
}
.bar-fill.success {
  background: #07c160;
}
.bar-fill.info {
  background: #8a94a6;
}
.bar-value {
  width: 56px;
  flex: none;
  font-variant-numeric: tabular-nums;
  font-size: 13px;
}
</style>
