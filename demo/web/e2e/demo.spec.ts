import { test, expect, type Page } from '@playwright/test'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
  const checkboxes = page.getByRole('checkbox')
  const count = await checkboxes.count()
  for (let i = 0; i < count; i++) {
    const cb = checkboxes.nth(i)
    if (await cb.isChecked()) await cb.click()
  }
  for (const label of labels) {
    await page.getByRole('checkbox', { name: new RegExp(label) }).check()
  }
}

async function generateProofAndWait(page: Page) {
  await page.getByRole('button', { name: /Згенерувати доказ|Generate/ }).click()
  await expect(
    page.getByText(/Доказ успішно згенеровано|Proof generated/).first()
  ).toBeVisible({ timeout: 180_000 })
}

// ---------------------------------------------------------------------------
// Landing Page
// ---------------------------------------------------------------------------

test.describe('Landing Page', () => {
  test('renders hero and key sections', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'zk-eidas', level: 2 })).toBeVisible()
    await expect(page.getByText(/Приватна верифікація|Privacy-Preserving/).first()).toBeVisible()
    // Capability triptych
    await expect(page.getByText(/Перевірка на стороні клієнта|Client-side/).first()).toBeVisible()
    // Live proof section
    await expect(page.getByText(/Спробуйте самі|Try it yourself/).first()).toBeVisible()
    // Paper contracts section
    await expect(page.getByText(/паперових контрактів|paper contracts/i).first()).toBeVisible()
    // Footer
    await expect(page.getByText(/Apache 2.0/).first()).toBeVisible()
  })
})

// ---------------------------------------------------------------------------
// Demo — Form + Issuance
// ---------------------------------------------------------------------------

test.describe('Demo — Page Load', () => {
  test('PID form loads with 5 credential types', async ({ page }) => {
    await page.goto('/demo')
    await expect(page.getByText(/Персональні ідентифікаційні|Personal Identification/).first()).toBeVisible()
    await expect(page.locator('input').first()).toBeVisible()
    await expect(page.getByRole('button', { name: /Видати посвідчення|Issue/ })).toBeVisible()
    await expect(page.locator('select option')).toHaveCount(5)
  })

  test('issuing PID shows predicate checkboxes', async ({ page }) => {
    await page.goto('/demo')
    await issueDefaultPid(page)
    await expect(page.getByRole('checkbox', { name: /щонайменше 18|at least 18/ })).toBeVisible()
    await expect(page.getByRole('checkbox', { name: /громадянство|nationality/i })).toBeVisible()
  })
})

// ---------------------------------------------------------------------------
// Demo — E2E Proof (PID age >= 18)
// ---------------------------------------------------------------------------

test.describe('Demo — E2E Proof', () => {
  test('PID: issue → prove age >= 18 → verified + hidden fields', async ({ page }) => {
    await page.goto('/demo')
    await issueDefaultPid(page)
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

test.describe('Demo — Print', () => {
  test('proof generates QR codes', async ({ page }) => {
    await page.goto('/demo')
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
    await page.goto('/contracts')
    await expect(page.getByText(/Перевірка віку|Age Verification/).first()).toBeVisible()
    await expect(page.getByText(/Студентський проїзний|Student Transit/).first()).toBeVisible()
    await expect(page.getByText(/найму водія|Driver Employment/).first()).toBeVisible()
    await expect(page.getByText(/купівлі-продажу|Vehicle Sale/).first()).toBeVisible()
  })

  test('clicking template advances wizard', async ({ page }) => {
    await page.goto('/contracts')
    await page.waitForTimeout(2000)
    await page.locator('button', { hasText: /Перевірка віку/ }).first().click()
    await expect(page.getByRole('button', { name: /Почати спочатку|Start over/ })).toBeVisible({ timeout: 15_000 })
  })
})

// ---------------------------------------------------------------------------
// Contracts — E2E (Age Verification)
// ---------------------------------------------------------------------------

test.describe('Contracts — E2E', () => {
  test('Age Verification: template → issue → prove → document', async ({ page }) => {
    await page.goto('/contracts')
    await page.waitForTimeout(2000)
    await page.locator('button', { hasText: /Перевірка віку/ }).first().click()
    await expect(page.getByRole('button', { name: /Почати спочатку|Start over/ })).toBeVisible({ timeout: 15_000 })
    const issueBtn = page.getByRole('button', { name: /Видати посвідчення|Issue/ })
    await issueBtn.scrollIntoViewIfNeeded()
    await issueBtn.click()
    await expect(page.getByText(/Доведені предикати|Proven predicates/i).first()).toBeVisible({ timeout: 30_000 })
    await page.getByRole('button', { name: /Згенерувати доказ|Generate proof/i }).click()
    await expect(page.getByRole('button', { name: /Друкувати|Print/i })).toBeVisible({ timeout: 180_000 })
  })
})

// ---------------------------------------------------------------------------
// i18n
// ---------------------------------------------------------------------------

test.describe('i18n', () => {
  test('EN/UA toggle works', async ({ page }) => {
    await page.goto('/')
    await page.waitForTimeout(2000)
    await expect(page.getByText(/Доведіть, хто ви є/).first()).toBeVisible()
    await page.getByRole('button', { name: 'EN' }).click()
    await expect(page.getByText(/Prove who you are/).first()).toBeVisible()
  })
})
