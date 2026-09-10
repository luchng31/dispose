import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from './stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/my' },
    { path: '/login', name: 'login', component: () => import('./views/Login.vue') },
    {
      path: '/my',
      name: 'my-tickets',
      component: () => import('./views/MyTickets.vue'),
      meta: { requiresAuth: true },
    },
    {
      path: '/my/:id',
      name: 'ticket-detail',
      component: () => import('./views/TicketDetail.vue'),
      meta: { requiresAuth: true },
    },
    // Task8: full operator/leader console (lazy-load, role-gated).
    // NOTE: stores/auth.ts untouched — no new getter needed; guard reads auth.role directly.
    // Pool reads allow leader (backend IsOperatorOrLeader); close/reject/ignore buttons
    // stay operator/admin-only via canShowOpsButton, and views still surface API 403
    // friendly messages (never rely on hiding/router-gating alone).
    {
      path: '/ops',
      name: 'ops-pool',
      component: () => import('./views/OpsPool.vue'),
      meta: { requiresAuth: true, roles: ['admin', 'operator', 'leader'] },
    },
    {
      path: '/ops/imports',
      name: 'import-mgmt',
      component: () => import('./views/ImportMgmt.vue'),
      meta: { requiresAuth: true, roles: ['admin', 'operator'] },
    },
    {
      path: '/ops/imports/assets',
      name: 'asset-owner-import',
      component: () => import('./views/AssetOwnerImport.vue'),
      meta: { requiresAuth: true, roles: ['admin', 'operator'] },
    },
    {
      path: '/ops/assets',
      name: 'asset-mapping',
      component: () => import('./views/AssetMapping.vue'),
      meta: { requiresAuth: true, roles: ['admin', 'operator', 'leader'] },
    },
    {
      path: '/ops/config',
      name: 'sys-config',
      component: () => import('./views/SysConfig.vue'),
      meta: { requiresAuth: true, roles: ['admin'] },
    },
    {
      path: '/ops/users',
      name: 'user-admin',
      component: () => import('./views/UsersView.vue'),
      meta: { requiresAuth: true, roles: ['admin', 'operator'] },
    },
    {
      path: '/ops/audit',
      name: 'audit-log',
      component: () => import('./views/AuditView.vue'),
      meta: { requiresAuth: true, roles: ['admin', 'operator', 'auditor'] },
    },
    {
      path: '/mfa',
      name: 'mfa-setup',
      component: () => import('./views/MfaSetup.vue'),
      meta: { requiresAuth: true },
    },
    { path: '/:pathMatch(.*)*', redirect: '/my' },
  ],
})

router.beforeEach((to) => {
  if (to.meta.requiresAuth && !localStorage.getItem('vuln_jwt')) {
    const auth = useAuthStore()
    auth.hydrate()
    if (!auth.isAuthenticated) {
      return { path: '/login', query: { redirect: to.fullPath } }
    }
  }
  const roles = to.meta.roles as string[] | undefined
  if (roles && roles.length > 0) {
    const auth = useAuthStore()
    auth.hydrate()
    const role = auth.role
    if (!role || !roles.includes(role)) {
      return { path: '/my' }
    }
  }
  return true
})

export default router
