import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import StatBars from '../components/StatBars.vue'

describe('StatBars', () => {
  it('renders labels, values and proportional widths', () => {
    const w = mount(StatBars, {
      props: {
        items: [
          { label: '逾期', value: 10, tone: 'danger' },
          { label: '正常', value: 5, tone: 'success' },
        ],
      },
    })
    expect(w.text()).toContain('逾期')
    expect(w.text()).toContain('10')
    const fills = w.findAll('.bar-fill')
    expect(fills).toHaveLength(2)
    expect(fills[0].attributes('style')).toContain('width: 100%')
    expect(fills[1].attributes('style')).toContain('width: 50%')
    expect(fills[0].classes()).toContain('danger')
  })

  it('renders 0% without dividing by zero', () => {
    const w = mount(StatBars, { props: { items: [{ label: '空', value: 0 }] } })
    expect(w.find('.bar-fill').attributes('style')).toContain('width: 0%')
  })
})
