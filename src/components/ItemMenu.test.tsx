import { describe, expect, it } from 'vitest'
import { menuShouldOpenUpward } from './ItemMenu'

describe('menuShouldOpenUpward', () => {
  it('opens upward when the menu would leave the bottom and fits above', () => {
    expect(menuShouldOpenUpward(700, 880, 160, 844)).toBe(true)
  })
  it('stays downward when the menu fits in the viewport', () => {
    expect(menuShouldOpenUpward(200, 360, 160, 844)).toBe(false)
  })
  it('stays downward when flipping would leave the top of the screen', () => {
    expect(menuShouldOpenUpward(20, 200, 180, 180)).toBe(false)
  })
})
