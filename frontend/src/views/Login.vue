<template>
  <el-container class="login-page">
    <el-main>
      <el-row justify="center">
        <el-col :xs="22" :sm="16" :md="12" :lg="8">
          <el-card header="漏洞修复工单系统 · 登录" v-loading="codeLoading">
            <template v-if="!showAdmin">
              <div class="qr-panel">
                <iframe
                  v-if="qrReady"
                  :src="qrUrl"
                  frameborder="0"
                  allowtransparency="true"
                  class="qr-frame"
                  title="企业微信扫码登录"
                />
                <div v-else class="qr-box">企微二维码</div>
                <p class="hint">
                  {{ qrReady ? '请使用企业微信扫码登录' : '企微扫码登录接入中（需配置 VITE_WECOM_CORPID / VITE_WECOM_AGENTID）' }}
                </p>
              </div>
              <el-alert
                v-if="codeError"
                :title="codeError"
                type="error"
                show-icon
                :closable="false"
                style="margin-top: 8px"
              />
              <el-divider><el-link type="info" :underline="false" @click="showAdmin = true">管理员入口</el-link></el-divider>
            </template>

            <template v-else>
              <el-form :model="form" label-width="90px" @submit.prevent="onLogin">
                <el-form-item label="用户名">
                  <el-input v-model="form.username" autocomplete="username" placeholder="管理员账号" />
                </el-form-item>
                <el-form-item label="密码">
                  <el-input v-model="form.password" type="password" show-password autocomplete="current-password" />
                </el-form-item>
                <el-form-item label="TOTP">
                  <el-input v-model="form.totp" placeholder="6位动态码（未启用可空）" maxlength="8" />
                </el-form-item>
                <el-form-item>
                  <el-button type="primary" :loading="loading" @click="onLogin">登录</el-button>
                  <el-button link @click="showAdmin = false">返回扫码登录</el-button>
                </el-form-item>
                <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" />
              </el-form>
            </template>
          </el-card>
        </el-col>
      </el-row>
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()

const showAdmin = ref(false)
const loading = ref(false)
const error = ref('')
const codeError = ref('')
const codeLoading = ref(false)

const wecomCorpid = import.meta.env.VITE_WECOM_CORPID as string | undefined
const wecomAgentId = import.meta.env.VITE_WECOM_AGENTID as string | undefined

const qrReady = computed(() => Boolean(wecomCorpid && wecomAgentId))
const qrUrl = computed(() => {
  if (!qrReady.value) return ''
  const redirect = encodeURIComponent(`${window.location.origin}/login`)
  return (
    'https://open.work.weixin.qq.com/wwopen/sso/qrConnect'
    + `?appid=${encodeURIComponent(wecomCorpid as string)}`
    + `&agentid=${encodeURIComponent(wecomAgentId as string)}`
    + `&redirect_uri=${redirect}&state=vuln_login`
  )
})

const form = reactive({ username: '', password: '', totp: '' })

async function exchangeCode(code: string) {
  codeLoading.value = true
  codeError.value = ''
  try {
    await auth.loginWecom(code)
    ElMessage.success('登录成功')
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/my'
    await router.replace(redirect)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { detail?: string } } }
    codeError.value = err.response?.data?.detail ?? '企微登录失败，请重试或使用管理员入口'
  } finally {
    codeLoading.value = false
  }
}

onMounted(() => {
  const code = typeof route.query.code === 'string' ? route.query.code : ''
  if (code && !codeLoading.value) void exchangeCode(code)
})

async function onLogin() {
  error.value = ''
  if (!form.username || !form.password) {
    error.value = '请输入用户名和密码'
    return
  }
  loading.value = true
  try {
    await auth.login(form.username, form.password, form.totp || undefined)
    ElMessage.success('登录成功')
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/my'
    await router.push(redirect)
  } catch (e: unknown) {
    const err = e as { response?: { status?: number; data?: { detail?: string } } }
    const status = err.response?.status
    if (status === 401) error.value = '用户名/密码或TOTP错误（401）'
    else if (status === 429) error.value = err.response?.data?.detail ?? '失败次数过多，账号已临时锁定，请稍后再试'
    else error.value = err.response?.data?.detail ?? '登录失败，请稍后重试'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  padding-top: 8vh;
}
.qr-panel {
  text-align: center;
}
.qr-frame {
  width: 100%;
  min-height: 400px;
}
.qr-box {
  width: 180px;
  height: 180px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px dashed #e7e7e7;
  color: #8a94a6;
}
.hint {
  color: #8a94a6;
  font-size: 12px;
}
</style>
