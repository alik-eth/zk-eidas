import { test, expect, type Page } from '@playwright/test'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function enableConsoleLogs(page: Page) {
  page.on('console', msg => {
    const text = msg.text()
    if (text.includes('[chunked-zkey]') || text.includes('[prover]') || text.includes('[worker]')) {
      console.log(`  [browser] ${text}`)
    }
  })
}

async function issueDefaultPid(page: Page) {
  page.on('dialog', d => d.dismiss())
  // Wait for React hydration
  await page.waitForTimeout(2000)
  const btn = page.getByRole('button', { name: /Видати посвідчення|Issue credential/ })
  await btn.scrollIntoViewIfNeeded()
  await btn.click()
  await expect(page.getByRole('checkbox').first()).toBeVisible({ timeout: 30_000 })
}

async function selectOnlyPredicates(page: Page, labels: string[]) {
  // First, uncheck all predicate checkboxes by targeting only visible ones with short timeout
  const checkboxes = page.getByRole('checkbox')
  const count = await checkboxes.count()
  for (let i = 0; i < count; i++) {
    const cb = checkboxes.nth(i)
    const visible = await cb.isVisible().catch(() => false)
    if (!visible) continue
    try {
      if (await cb.isChecked({ timeout: 1000 })) await cb.click()
    } catch {
      continue
    }
  }
  for (const label of labels) {
    await page.getByRole('checkbox', { name: new RegExp(label) }).check()
  }
}

async function generateProofAndWait(page: Page, timeoutMs = 600_000) {
  // Match both server ("Згенерувати доказ/Generate") and on-device ("Довести у браузері/Prove in browser") buttons
  await page.getByRole('button', { name: /Згенерувати доказ|Generate|Довести у браузері|Prove in browser/ }).click()
  await expect(
    page.getByText(/Доказ успішно згенеровано|Proof generated/).first()
  ).toBeVisible({ timeout: timeoutMs })
}

// ---------------------------------------------------------------------------
// Landing Page
// ---------------------------------------------------------------------------

test.describe('Landing Page', () => {
  test('renders hero and key sections', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'zk-eidas', level: 2 })).toBeVisible()
    // Subtitle
    await expect(page.getByText(/Доведіть, хто ви є|Prove who you are/i).first()).toBeVisible()
    // Problem section
    await expect(page.getByText(/Проблема з цифровими ID|problem with EU digital/i).first()).toBeVisible()
    // Live proof section
    await expect(page.getByText(/Спробуйте прямо зараз|Try it right now/i).first()).toBeVisible()
    // Paper contracts section
    await expect(page.getByText(/Контракти без персональних даних|Contracts without personal data/i).first()).toBeVisible()
    // Footer
    await expect(page.getByText(/Apache 2.0/).first()).toBeVisible()
  })
})

// ---------------------------------------------------------------------------
// Learn Page
// ---------------------------------------------------------------------------

test.describe('Learn Page', () => {
  test('renders all 8 sections', async ({ page }) => {
    await page.goto('/learn')
    // Section 1: eIDAS problem
    await expect(page.getByText(/eIDAS 2.0|Доведіть, хто ви є|Prove who you are/).first()).toBeVisible()
    // Section 3: Comparison table
    await expect(page.getByText(/SD-JWT VC/).first()).toBeVisible()
    await expect(page.getByText(/BBS\+/).first()).toBeVisible()
    // Section 4: Trust gap
    await expect(page.getByText(/Trust Gap|Прогалина довіри/).first()).toBeVisible()
    // Section 7: Standards
    await expect(page.getByText(/SOG-IS/).first()).toBeVisible()
    await expect(page.getByText(/POTENTIAL/).first()).toBeVisible()
    // Section 8: GDPR
    await expect(page.getByText(/GDPR/).first()).toBeVisible()
    // CTA
    await expect(page.getByRole('link', { name: /Спробувати|Try/ })).toBeVisible()
  })
})

// ---------------------------------------------------------------------------
// Demo — Form + Issuance
// ---------------------------------------------------------------------------

test.describe('Sandbox — Page Load', () => {
  test('PID form loads with 5 credential types', async ({ page }) => {
    await page.goto('/sandbox')
    await expect(page.getByText(/Персональні ідентифікаційні|Personal Identification/).first()).toBeVisible()
    await expect(page.locator('input').first()).toBeVisible()
    await expect(page.getByRole('button', { name: /Видати посвідчення|Issue/ })).toBeVisible()
    await expect(page.locator('select option')).toHaveCount(5)
  })

  test('issuing PID shows predicate checkboxes', async ({ page }) => {
    await page.goto('/sandbox')
    await issueDefaultPid(page)
    await expect(page.getByRole('checkbox', { name: /щонайменше 18|at least 18/ })).toBeVisible()
    await expect(page.getByRole('checkbox', { name: /громадянство|nationality/i })).toBeVisible()
  })
})

// ---------------------------------------------------------------------------
// Demo — E2E Proof (PID age >= 18)
// ---------------------------------------------------------------------------

test.describe('Sandbox — E2E Proof', () => {
  test('PID: issue → prove age >= 18 → verified + hidden fields', async ({ page }) => {
    await page.goto('/sandbox')
    await issueDefaultPid(page)
    await selectOnlyPredicates(page, ['щонайменше 18|at least 18'])
    await generateProofAndWait(page)
    await expect(page.getByText(/birth_date|age_over_18|Дата народж|Вік понад 18/).first()).toBeVisible()
    await expect(page.getByText('██████').first()).toBeVisible()
    await expect(page.getByRole('link', { name: /Зберегти доказ|Save proof/ })).toBeVisible()
  })
})

// ---------------------------------------------------------------------------
// Demo — On-Device Proof (browser-side proving via snarkjs)
// ---------------------------------------------------------------------------

test.describe('Sandbox — On-Device Proof', () => {
  // Skip by default: ECDSA proving takes ~3 min in the browser.
  // Run manually: E2E_ON_DEVICE=1 npx playwright test --grep "On-Device"
  test.skip(() => !process.env.E2E_ON_DEVICE, 'slow: set E2E_ON_DEVICE=1 to run')

  test('PID: issue → on-device prove age >= 18 → verified', async ({ page }) => {
    test.setTimeout(600_000) // 10 min — ECDSA circuit is heavy in browser
    enableConsoleLogs(page)
    await page.goto('/sandbox')
    await issueDefaultPid(page)

    // Toggle to "On Device" proving
    await page.getByRole('button', { name: /On Device/ }).click()

    await selectOnlyPredicates(page, ['щонайменше 18|at least 18'])
    await generateProofAndWait(page)
    await expect(page.getByText(/birth_date|age_over_18|Дата народж|Вік понад 18/).first()).toBeVisible()
    await expect(page.getByText('██████').first()).toBeVisible()
    await expect(page.getByRole('link', { name: /Зберегти доказ|Save proof/ })).toBeVisible()
  })
})

// ---------------------------------------------------------------------------
// Demo — Print (QR codes)
// ---------------------------------------------------------------------------

test.describe('Sandbox — Print', () => {
  test('proof generates QR codes', async ({ page }) => {
    await page.goto('/sandbox')
    await issueDefaultPid(page)
    await selectOnlyPredicates(page, ['щонайменше 18|at least 18'])
    await generateProofAndWait(page)
    await page.getByRole('button', { name: /Сформувати засвідчення|attestation/i }).click()
    await expect(page.locator('img[alt*="QR"]').first()).toBeVisible({ timeout: 30_000 })
    expect(await page.locator('img[alt*="QR"]').count()).toBeGreaterThan(0)
    await expect(page.getByRole('button', { name: /Друкувати|Print/i })).toBeVisible()
  })
})

// ---------------------------------------------------------------------------
// Verify Page
// ---------------------------------------------------------------------------

test.describe('Verify Page', () => {
  test('renders CBOR drop zone and QR scanner', async ({ page }) => {
    await page.goto('/verify')
    await expect(page.getByText(/\.cbor/).first()).toBeVisible()
    await expect(page.getByRole('button', { name: /Сканувати|Scan/i })).toBeVisible()
  })
})

// ---------------------------------------------------------------------------
// Contracts
// ---------------------------------------------------------------------------

test.describe('Contracts', () => {
  test('shows all 4 templates', async ({ page }) => {
    await page.goto('/demo')
    await expect(page.getByText(/Перевірка віку|Age Verification/).first()).toBeVisible()
    await expect(page.getByText(/Студентський проїзний|Student Transit/).first()).toBeVisible()
    await expect(page.getByText(/найму водія|Driver Employment/).first()).toBeVisible()
    await expect(page.getByText(/купівлі-продажу|Vehicle Sale/).first()).toBeVisible()
  })

  test('/contracts redirects to /demo', async ({ page }) => {
    await page.goto('/contracts')
    await page.waitForURL('/demo')
    await expect(page.getByText(/Перевірка віку|Age Verification/).first()).toBeVisible()
  })

  test('clicking template advances wizard', async ({ page }) => {
    await page.goto('/demo')
    await page.waitForTimeout(2000)
    await page.locator('button', { hasText: /Перевірка віку/ }).first().click()
    await expect(page.getByRole('button', { name: /Почати спочатку|Start over/ })).toBeVisible({ timeout: 15_000 })
  })
})

// ---------------------------------------------------------------------------
// Contracts — E2E (Age Verification)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Contracts — E2E (all 4 templates, server + on-device modes with benchmarks)
// ---------------------------------------------------------------------------

const ON_DEVICE = !!process.env.E2E_ON_DEVICE
const CONTRACT_TEMPLATES = [
  // ecdsaProofs = unique predicate claims + nullifier field (if different from predicate claims)
  { name: 'Age Verification', pattern: /Перевірка віку/, creds: 1, ecdsaProofs: 2 },
  { name: 'Student Transit', pattern: /Студентський проїзний|Student Transit/, creds: 1, ecdsaProofs: 2 },
  { name: 'Driver Employment', pattern: /найму водія|Driver Employment/, creds: 1, ecdsaProofs: 4 },
  { name: 'Vehicle Sale', pattern: /купівлі-продажу|Vehicle Sale/, creds: 3, ecdsaProofs: 6 },
]

for (const tpl of CONTRACT_TEMPLATES) {
  const mode = ON_DEVICE ? 'on-device' : 'server'

  test.describe(`Contract: ${tpl.name} (${mode})`, () => {
    if (ON_DEVICE) {
      test.skip(() => !process.env.E2E_ON_DEVICE, 'slow: set E2E_ON_DEVICE=1 to run')
    }

    test(`${tpl.name}: issue ${tpl.creds} cred(s) → prove → document`, async ({ page }) => {
      // Each ECDSA proof takes ~5 min in browser; scale timeout accordingly
      const timeoutMs = ON_DEVICE ? tpl.ecdsaProofs * 5 * 60_000 : 300_000
      test.setTimeout(timeoutMs)
      if (ON_DEVICE) enableConsoleLogs(page)

      // Collect benchmark timings from browser console
      const timings: string[] = []
      page.on('console', msg => {
        const text = msg.text()
        if (text.includes('Proof generated') || text.includes('Verification:')) {
          timings.push(text)
        }
      })

      // 1. Select template
      await page.goto('/demo')
      await page.waitForTimeout(2000)
      await page.locator('button', { hasText: tpl.pattern }).first().click()
      await expect(page.getByRole('button', { name: /Почати спочатку|Start over/ })).toBeVisible({ timeout: 15_000 })

      // 2. Issue credential(s)
      const issueStart = Date.now()
      for (let i = 0; i < tpl.creds; i++) {
        const issueBtn = page.getByRole('button', { name: /Видати посвідчення|Issue/ })
        await issueBtn.scrollIntoViewIfNeeded()
        await issueBtn.click()
        if (i < tpl.creds - 1) await page.waitForTimeout(1000)
      }
      await expect(page.getByText(/Доведені предикати|Proven predicates/i).first()).toBeVisible({ timeout: 30_000 })
      const issueMs = Date.now() - issueStart

      // 3. Toggle mode if on-device
      if (ON_DEVICE) {
        await page.getByRole('button', { name: /On Device/ }).click()
      }

      // 4. Prove
      const proveStart = Date.now()
      await generateProofAndWait(page, timeoutMs)
      const proveMs = Date.now() - proveStart

      // 5. Verify document generated
      await expect(page.getByRole('button', { name: /Друкувати|Print/i })).toBeVisible({ timeout: 600_000 })

      // 6. Print benchmarks
      const totalMs = issueMs + proveMs
      console.log(`\n  ⏱  ${tpl.name} (${mode}) benchmarks:`)
      console.log(`     Issuance:  ${(issueMs / 1000).toFixed(1)}s`)
      console.log(`     Proving:   ${(proveMs / 1000).toFixed(1)}s`)
      console.log(`     Total:     ${(totalMs / 1000).toFixed(1)}s`)
      if (timings.length > 0) {
        console.log(`     Details:`)
        for (const t of timings) console.log(`       ${t.replace(/^\[worker\] /, '')}`)
      }
    })
  })
}

// ---------------------------------------------------------------------------
// i18n
// ---------------------------------------------------------------------------

test.describe('i18n', () => {
  test('EN/UA toggle works', async ({ page }) => {
    await page.goto('/')
    await page.waitForTimeout(2000)
    await expect(page.getByText(/Доведіть, хто ви є/).first()).toBeVisible()
    await page.getByRole('button', { name: 'EN' }).click()
    await expect(page.getByText(/Prove who you are/i).first()).toBeVisible()
  })
})
