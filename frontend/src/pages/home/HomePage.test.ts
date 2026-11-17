import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import HomePage from './HomePage.vue'
import { getVersion } from '../../shared/api/version'

vi.mock('../../shared/api/version', () => ({ getVersion: vi.fn() }))

describe('HomePage', () => {
  it('показывает версию из Go', async () => {
    vi.mocked(getVersion).mockResolvedValue('1.2.3')
    const w = mount(HomePage)
    await flushPromises()
    expect(w.get('[data-test="version"]').text()).toBe('v1.2.3')
  })

  it('показывает ошибку, если Go не ответил', async () => {
    vi.mocked(getVersion).mockRejectedValue(new Error('no bridge'))
    const w = mount(HomePage)
    await flushPromises()
    expect(w.text()).toContain('Нет связи с Go')
    expect(w.find('[data-test="version"]').exists()).toBe(false)
  })
})
