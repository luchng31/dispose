<template>
  <el-timeline v-if="groups.length">
    <el-timeline-item
      v-for="g in groups"
      :key="g.key"
      :type="g.current ? 'primary' : 'info'"
      :timestamp="currentLabel(g)"
    >
      {{ g.username || g.wecom_userid || g.key }}
      <span class="muted">({{ g.periods.length }} 段)</span>
      <ul class="periods">
        <li v-for="(p, i) in g.periods" :key="i" class="muted">
          {{ String(p.valid_from ?? '-') }} → {{ String(p.valid_to ?? '至今') }}
        </li>
      </ul>
    </el-timeline-item>
  </el-timeline>
  <el-empty v-else description="暂无映射历史" />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { groupMappingHistory, type MappingHistoryGroup, type MappingRow } from '../utils/ops'

const props = defineProps<{ history: MappingRow[] }>()

const groups = computed<MappingHistoryGroup[]>(() => groupMappingHistory(props.history))

function currentLabel(g: MappingHistoryGroup): string {
  return g.current ? '现任' : '历史'
}
</script>

<style scoped>
.muted {
  color: #999;
  font-size: 12px;
}
.periods {
  margin: 4px 0 0;
  padding-left: 16px;
}
</style>
