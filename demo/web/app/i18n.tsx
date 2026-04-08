import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";

export type Locale = "en" | "uk";

const STORAGE_KEY = "zk-eidas-locale";
const DEFAULT_LOCALE: Locale = "uk";

// ---------------------------------------------------------------------------
// Translations
// ---------------------------------------------------------------------------

const translations: Record<string, Record<Locale, string>> = {
  // ── Navigation ──────────────────────────────────────────────────────────
  "nav.verify": { en: "Verify", uk: "Верифікація" },
  "nav.demo": { en: "Playground", uk: "Пісочниця" },
  "nav.github": { en: "GitHub", uk: "GitHub" },

  // ── Hero ────────────────────────────────────────────────────────────────
  "hero.subtitle": {
    en: "Europe promised digital identity. The hard part isn't the wallet — it's proving things without a central registry.",
    uk: "Європа пообіцяла цифрову ідентичність. Складність не в гаманці — а в доведенні без центрального реєстру.",
  },
  "hero.tagline": {
    en: "Zero-knowledge proofs for eIDAS 2.0 — no trusted setup, no central database, no surveillance.",
    uk: "Докази з нульовим знанням для eIDAS 2.0 — без довіреної ініціалізації, без центральної бази, без стеження.",
  },
  "hero.tryDemo": { en: "Try the Demo", uk: "Спробувати демо" },
  "hero.viewGithub": { en: "View on GitHub", uk: "Переглянути на GitHub" },

  // ── The Dilemma ─────────────────────────────────────────────────────
  "dilemma.title": {
    en: "The Dilemma",
    uk: "Дилема",
  },
  "dilemma.gapTitle": {
    en: "The Digital-Physical Gap",
    uk: "Цифрово-фізичний розрив",
  },
  "dilemma.gapDesc": {
    en: "Citizens still carry paper documents. Digital credentials exist, but verification means full disclosure or online registry lookups. Physical bureaucracy persists because digital identity hasn't solved the trust problem.",
    uk: "Громадяни досі носять паперові документи. Цифрові посвідчення існують, але верифікація означає повне розкриття або онлайн-запити до реєстрів. Паперова бюрократія зберігається, бо цифрова ідентичність не вирішила проблему довіри.",
  },
  "dilemma.promiseTitle": {
    en: "The Promise of eIDAS 2.0",
    uk: "Обіцянка eIDAS 2.0",
  },
  "dilemma.promiseDesc": {
    en: "Article 5a(16) mandates selective disclosure and unlinkability. Wallets should let you prove \"I'm over 18\" without revealing your name or birthdate. The regulation is right — the implementation is the challenge.",
    uk: "Стаття 5a(16) вимагає селективного розкриття та незв'язуваності. Гаманці мають дозволяти довести \"мені є 18\" без розкриття імені чи дати народження. Регламент правильний — проблема в реалізації.",
  },
  "dilemma.centralTitle": {
    en: "The Centralization Problem",
    uk: "Проблема централізації",
  },
  "dilemma.centralDesc": {
    en: "The EU can't — and shouldn't — centralize 27 member state registries. No single authority can be the verifier of last resort. The system must work without a central database.",
    uk: "ЄС не може — і не повинен — централізувати реєстри 27 держав-членів. Жодна єдина інстанція не може бути верифікатором останньої інстанції. Система має працювати без центральної бази даних.",
  },
  "dilemma.web3Title": {
    en: "The Web3 Identity Gap",
    uk: "Розрив ідентичності Web3",
  },
  "dilemma.web3Desc": {
    en: "Blockchain wallets are pseudonymous. KYC is bolted on through centralized providers — recreating the gatekeepers decentralization was meant to remove. With zk-eidas, blockchain becomes a consumer of government-issued credentials, not a replacement. Prove you're an EU citizen without revealing your name. Nullifiers prevent double-registration. Court-ordered deanonymization ensures compliance.",
    uk: "Блокчейн-гаманці псевдонімні. KYC нав'язується через централізованих провайдерів — відтворюючи посередників, від яких децентралізація мала позбавити. З zk-eidas блокчейн стає споживачем державних посвідчень, а не їх заміною. Доведіть, що ви громадянин ЄС, не розкриваючи імені. Нуліфікатори запобігають подвійній реєстрації. Розкриття за рішенням суду забезпечує відповідність.",
  },

  // ── The Proposal (brief on root) ────────────────────────────────────
  "rootProposal.title": {
    en: "A Proposal for Trust Service Providers",
    uk: "Пропозиція для довірених постачальників послуг",
  },
  "rootProposal.attestDesc": {
    en: "A Qualified TSP verifies a zero-knowledge proof and issues a signed attestation (QEAA). At ~1-2 KB, it fits in a single QR code — verifiable offline, legally meaningful under eIDAS 2.0.",
    uk: "Кваліфікований TSP перевіряє доказ з нульовим знанням і видає підписану атестацію (QEAA). Розміром ~1-2 КБ, вона поміщається в один QR-код — перевіряється офлайн, юридично значуща за eIDAS 2.0.",
  },
  "rootProposal.escrowDesc": {
    en: "The TSP holds the decryption key for identity escrow. Encrypted credential fields are released only on court order — accountability without surveillance.",
    uk: "TSP зберігає ключ дешифрування для ескроу ідентичності. Зашифровані поля посвідчень розкриваються лише за рішенням суду — підзвітність без стеження.",
  },
  "rootProposal.cta": {
    en: "Read the full TSP proposal",
    uk: "Читати повну пропозицію TSP",
  },
  "rootProposal.learnMore": {
    en: "How it works — the technical details",
    uk: "Як це працює — технічні деталі",
  },

  // ── Problem ──────────────────────────────────────────────────────────
  "problem.title": {
    en: "The problem with EU digital IDs",
    uk: "Проблема з цифровими ID ЄС",
  },
  "problem.subtitle": {
    en: "EU law says your digital ID should be private — no one should track where you use it. But the formats chosen for eIDAS 2.0 can't do that. Every time you show your credential, it carries the same signature — like a fingerprint that follows you everywhere.",
    uk: "Закон ЄС каже, що ваш цифровий ID має бути приватним — ніхто не повинен відстежувати, де ви його використовуєте. Але обрані для eIDAS 2.0 формати не можуть цього забезпечити. Щоразу, коли ви показуєте посвідчення, воно несе той самий підпис — як відбиток пальця, що слідує за вами всюди.",
  },
  "problem.criterion": { en: "Criterion", uk: "Критерій" },
  "problem.sdjwt": { en: "SD-JWT VC", uk: "SD-JWT VC" },
  "problem.bbs": { en: "BBS+", uk: "BBS+" },
  "problem.batch": { en: "Batch Issuance", uk: "Пакетна видача" },
  "problem.zk": { en: "ZK Proofs", uk: "ZK-докази" },
  "problem.row1": { en: "Works with existing EU credentials", uk: "Працює з існуючими посвідченнями ЄС" },
  "problem.row2": { en: "EU-approved cryptography", uk: "Схвалена ЄС криптографія" },
  "problem.row3": { en: "Can't be tracked across services", uk: "Неможливо відстежити між сервісами" },
  "problem.row4": { en: "Show only what's needed", uk: "Показує лише необхідне" },
  "problem.row5": { en: "Prove facts without raw data (e.g. age \u2265 18)", uk: "Доведення фактів без сирих даних (напр. вік \u2265 18)" },
  "problem.row6": { en: "No changes to existing systems", uk: "Без змін існуючих систем" },

  // ── Learn More page ─────────────────────────────────────────────────────
  "learn.back": { en: "Back", uk: "Назад" },
  "learn.title": { en: "Why Zero-Knowledge for eIDAS 2.0", uk: "Чому Zero-Knowledge для eIDAS 2.0" },
  "learn.subtitle": {
    en: "eIDAS 2.0 mandates unlinkability. The approved credential formats cannot provide it. Zero-knowledge proofs are the only compliant solution.",
    uk: "eIDAS 2.0 вимагає незв'язуваності. Затверджені формати посвідчень не можуть її забезпечити. Докази з нульовим розголошенням — єдине відповідне рішення.",
  },
  "learn.cta": { en: "Try the Playground", uk: "Спробувати пісочницю" },

  // TOC
  "learn.tocComparison": { en: "Comparison", uk: "Порівняння" },
  "learn.tocStandards": { en: "Standards", uk: "Стандарти" },

  // 3. Comparison Table
  "learn.comparisonTitle": { en: "Approach Comparison", uk: "Порівняння підходів" },
  "learn.comparisonSubtitle": {
    en: "Four approaches to credential presentation privacy — only one satisfies all eIDAS 2.0 requirements.",
    uk: "Чотири підходи до приватності пред'явлення посвідчень — лише один задовольняє всі вимоги eIDAS 2.0.",
  },
  "learn.compCriterion": { en: "Criterion", uk: "Критерій" },
  "learn.compSdjwt": { en: "SD-JWT VC", uk: "SD-JWT VC" },
  "learn.compBbs": { en: "BBS+", uk: "BBS+" },
  "learn.compBatch": { en: "Batch Issuance", uk: "Пакетна видача" },
  "learn.compZk": { en: "ZK (zk-eidas)", uk: "ZK (zk-eidas)" },
  "learn.compUnlinkability": { en: "Unlinkability", uk: "Незв'язуваність" },
  "learn.compUnlinkSdjwt": { en: "Signature is constant", uk: "Підпис постійний" },
  "learn.compUnlinkBbs": { en: "Derived proofs", uk: "Похідні докази" },
  "learn.compUnlinkBatch": { en: "Limited by N copies", uk: "Обмежено N копіями" },
  "learn.compUnlinkZk": { en: "Unique per presentation", uk: "Унікальний для кожного пред'явлення" },
  "learn.compSelective": { en: "Selective Disclosure", uk: "Селективне розкриття" },
  "learn.compSelectSdjwt": { en: "Per-claim hashes", uk: "Хеші по полях" },
  "learn.compSelectBbs": { en: "Native", uk: "Нативне" },
  "learn.compSelectBatch": { en: "Full credential", uk: "Повне посвідчення" },
  "learn.compSelectZk": { en: "Boolean predicates", uk: "Булеві предикати" },
  "learn.compPredicates": { en: "Predicates (e.g., age≥18)", uk: "Предикати (напр., вік≥18)" },
  "learn.compPredReveals": { en: "Reveals raw value", uk: "Розкриває сире значення" },
  "learn.compPredZk": { en: "Proves without revealing", uk: "Доводить без розкриття" },
  "learn.compSogis": { en: "SOG-IS Approved Crypto", uk: "Схвалена SOG-IS криптографія" },
  "learn.compSogisSdjwt": { en: "ECDSA P-256", uk: "ECDSA P-256" },
  "learn.compSogisBbs": { en: "Not approved", uk: "Не схвалено" },
  "learn.compSogisBatch": { en: "ECDSA P-256", uk: "ECDSA P-256" },
  "learn.compSogisZk": { en: "ECDSA P-256 + SHA-256", uk: "ECDSA P-256 + SHA-256" },
  "learn.compOffline": { en: "Offline Verification", uk: "Офлайн верифікація" },
  "learn.compFormat": { en: "Credential Format", uk: "Формат посвідчення" },
  "learn.compFormatSdjwt": { en: "Native SD-JWT", uk: "Нативний SD-JWT" },
  "learn.compFormatBbs": { en: "New format required", uk: "Потрібен новий формат" },
  "learn.compFormatBatch": { en: "Native SD-JWT", uk: "Нативний SD-JWT" },
  "learn.compFormatZk": { en: "Native mdoc", uk: "Нативний mdoc" },
  "learn.compSize": { en: "Proof Size", uk: "Розмір доказу" },
  "learn.compSizeFull": { en: "Full disclosed claims", uk: "Повні розкриті поля" },
  "learn.compSizeBbs": { en: "~200 bytes", uk: "~200 байт" },
  "learn.compSizeZk": { en: "~360 KB (QEAA: ~1-2 KB)", uk: "~360 КБ (QEAA: ~1-2 КБ)" },
  "learn.compFootSdjwt": {
    en: "SD-JWT VC: RFC 9901. Selective disclosure via salted hashes, but the issuer's signature is constant across all presentations — a persistent correlation handle.",
    uk: "SD-JWT VC: RFC 9901. Селективне розкриття через хеші з сіллю, але підпис видавця постійний у всіх пред'явленнях — стійкий маркер кореляції.",
  },
  "learn.compFootBbs": {
    en: "BBS+: Mathematically sound unlinkability, but relies on bilinear pairings not on the SOG-IS approved list. Rejected by the European Commission for EUDI Wallets.",
    uk: "BBS+: Математично обґрунтована незв'язуваність, але використовує білінійні спарювання, відсутні у переліку SOG-IS. Відхилено Європейською Комісією для EUDI Wallets.",
  },
  "learn.compFootBatch": {
    en: "Batch Issuance: Multiple credential copies with rotating keys. Storage scales linearly with N, revocation becomes per-copy, and N must be predetermined.",
    uk: "Пакетна видача: кілька копій посвідчень з ротацією ключів. Зберігання масштабується лінійно з N, відкликання стає по-копійним, N треба визначити заздалегідь.",
  },

  // Escrow UI (shared between sandbox and contracts)
  "escrow.toggle": { en: "Identity Escrow", uk: "Ідентіті ескроу" },
  "escrow.toggleDesc": {
    en: "Encrypt personal data inside the proof — decryption only by escrow authority",
    uk: "Зашифрувати персональні дані в доказі — розшифровка тільки ескроу-органом",
  },
  "escrow.fieldsLabel": { en: "Fields to encrypt", uk: "Поля для шифрування" },
  "escrow.lockedFieldsLabel": {
    en: "Encrypted fields (required for court filing)",
    uk: "Зашифровані поля (потрібні для подання до суду)",
  },
  "escrow.ecdsaBinding": { en: "ECDSA binding claim", uk: "ECDSA-прив'язка" },
  "escrow.keypairGenerated": { en: "Throwaway keypair generated", uk: "Одноразову пару ключів згенеровано" },
  "escrow.envelopeTitle": { en: "Escrow Envelope", uk: "Ескроу-конверт" },
  "escrow.credentialHash": { en: "Credential hash", uk: "Хеш посвідчення" },
  "escrow.ciphertext": { en: "Ciphertext", uk: "Шифротекст" },
  "escrow.keyCommitment": { en: "Key commitment", uk: "Комітмент ключа" },
  "escrow.authorityPubkey": { en: "Authority pubkey", uk: "Публічний ключ органу" },
  "escrow.decryptBtn": { en: "Decrypt as Authority", uk: "Розшифрувати як орган" },
  "escrow.decryptedTitle": { en: "Decrypted Identity", uk: "Розшифрована особа" },
  "escrow.decrypting": { en: "Decrypting...", uk: "Розшифровуємо..." },
  "escrow.authorityLabel": { en: "Escrow Authority", uk: "Ескроу-авторитет" },
  "escrow.fingerprint": { en: "Fingerprint", uk: "Відбиток" },
  "doc.proofLabel": { en: "P", uk: "P" },
  "doc.escrowLabel": { en: "E", uk: "E" },
  "escrow.qrLabel": { en: "Escrow Envelope (ML-KEM-768)", uk: "Ескроу-конверт (ML-KEM-768)" },
  "escrow.qrSubtitle": {
    en: "Post-quantum encrypted. Decryption only by escrow authority.",
    uk: "Постквантове шифрування. Розшифровка тільки ескроу-органом.",
  },

  // 7. Standards & Compliance
  "learn.standardsTitle": { en: "Standards & Compliance", uk: "Стандарти та відповідність" },
  "learn.standardsSubtitle": {
    en: "Built natively for eIDAS 2.0 — not retrofitted. Every cryptographic primitive is SOG-IS approved.",
    uk: "Розроблено нативно для eIDAS 2.0 — не адаптовано. Кожен криптографічний примітив схвалений SOG-IS.",
  },
  "learn.stdEidas": {
    en: "The EU Digital Identity Framework mandating digital wallets for all EU citizens. zk-eidas supports the PID credential profile specified in the Architecture Reference Framework.",
    uk: "Рамка цифрової ідентичності ЄС, що зобов'язує цифрові гаманці для всіх громадян ЄС. zk-eidas підтримує профіль PID, визначений у Architecture Reference Framework.",
  },
  "learn.stdSdjwt": {
    en: "Selective Disclosure for JWTs (RFC 9901). Not currently supported by the Longfellow proving backend. mdoc (ISO 18013-5) is the supported credential format for v2.0.",
    uk: "Selective Disclosure для JWT (RFC 9901). Наразі не підтримується бекендом доведення Longfellow. mdoc (ISO 18013-5) є підтримуваним форматом посвідчень для v2.0.",
  },
  "learn.stdMdoc": {
    en: "Mobile document format with COSE_Sign1 signatures (ISO 18013-5). The primary credential format for zk-eidas v2.0. Longfellow verifies COSE_Sign1 signatures natively during proof generation.",
    uk: "Формат мобільних документів з підписами COSE_Sign1 (ISO 18013-5). Основний формат посвідчень для zk-eidas v2.0. Longfellow перевіряє підписи COSE_Sign1 нативно під час генерації доказу.",
  },
  "learn.stdEcdsa": {
    en: "The signature algorithm specified by mdoc (COSE_Sign1). P-256 curve, verified natively by the Longfellow prover for every proof.",
    uk: "Алгоритм підпису, визначений для mdoc (COSE_Sign1). Крива P-256, перевіряється нативно довідником Longfellow для кожного доказу.",
  },
  "learn.stdOpenid": {
    en: "The transport protocol for requesting and receiving ZK proofs from EUDI Wallets.",
    uk: "Транспортний протокол для запиту та отримання ZK доказів від EUDI Wallets.",
  },
  "learn.stdArf": {
    en: "Compatible with Architecture Reference Framework (ARF) PID and mDL credential profiles. Conformance tests validate against the exact ARF credential schemas.",
    uk: "Сумісний з Architecture Reference Framework (ARF) профілями PID та mDL. Тести відповідності валідують саме ARF схеми посвідчень.",
  },
  "learn.stdSogis": {
    en: "All cryptographic primitives (ECDSA P-256, SHA-256, AES-256-GCM, ML-KEM-768) are SOG-IS approved or NIST standardized. The proving system (Sumcheck+Ligero) uses only hash-based commitments — no pairing-based trusted setup.",
    uk: "Всі криптографічні примітиви (ECDSA P-256, SHA-256, AES-256-GCM, ML-KEM-768) затверджені SOG-IS або стандартизовані NIST. Система доведення (Sumcheck+Ligero) використовує лише хеш-засновані зобов'язання — без довіреної ініціалізації на основі пейрингів.",
  },
  "learn.stdPotential": {
    en: "Aligned with POTENTIAL Large-Scale Pilot specifications for cross-border credential verification.",
    uk: "Вирівняно зі специфікаціями пілоту великого масштабу POTENTIAL для транскордонної верифікації посвідчень.",
  },

  // 8. GDPR
  "learn.privacyTitle": { en: "GDPR: Privacy by Design", uk: "GDPR: Приватність за дизайном" },
  "learn.privacyDesc": {
    en: "zk-eidas implements GDPR's data minimization principle at the cryptographic level. Zero-knowledge proofs reveal only boolean predicate results — never raw personal data.",
    uk: "zk-eidas реалізує принцип мінімізації даних GDPR на криптографічному рівні. Докази з нульовим розголошенням розкривають лише булеві результати предикатів — ніколи сирі персональні дані.",
  },
  "learn.privacyMinimization": { en: "Data Minimization", uk: "Мінімізація даних" },
  "learn.privacyMinimizationDesc": { en: "Proofs reveal only boolean results. No raw claim values ever leave the holder.", uk: "Докази розкривають лише булеві результати. Жодне сире значення не залишає власника." },
  "learn.privacyLimitation": { en: "Purpose Limitation", uk: "Обмеження цілей" },
  "learn.privacyLimitationDesc": { en: "Each proof is scoped to a specific predicate. A verifier cannot repurpose it for other checks.", uk: "Кожен доказ прив'язаний до конкретного предиката. Верифікатор не може використати його для інших перевірок." },
  "learn.privacyStorage": { en: "Zero Storage", uk: "Нуль зберігання" },
  "learn.privacyStorageDesc": { en: "The library stores no personal data. Proofs are transient. Nothing to breach.", uk: "Бібліотека не зберігає персональних даних. Докази тимчасові. Нічого для витоку." },

  // ── Learn More nav ───────────────────────────────────────────────────
  "nav.learn": { en: "Learn More", uk: "Дізнатися більше" },

  // ── Learn: 7-stage pipeline ─────────────────────────────────────────
  "learn.pipelineTitle": {
    en: "How It Works",
    uk: "Як це працює",
  },
  "learn.pipelineSubtitle": {
    en: "From credential to verified attestation in seven stages.",
    uk: "Від посвідчення до верифікованої атестації за сім етапів.",
  },
  "learn.stage1Title": { en: "1. Credential", uk: "1. Посвідчення" },
  "learn.stage1Desc": {
    en: "The input to the system is an mdoc credential (ISO 18013-5) signed with COSE_Sign1. This is the mobile document format used for driving licenses and national IDs across the EU. Each credential contains claims (name, birthdate, nationality) signed by an issuer authority. SD-JWT is not currently supported by the Longfellow proving backend.",
    uk: "Вхідними даними системи є посвідчення mdoc (ISO 18013-5), підписане COSE_Sign1. Це формат мобільних документів, що використовується для водійських посвідчень та національних ID в ЄС. Кожне посвідчення містить поля (ім'я, дата народження, громадянство), підписані інстанцією-видавцем. SD-JWT наразі не підтримується бекендом доведення Longfellow.",
  },
  "learn.stage2Title": { en: "2. Parse", uk: "2. Розбір" },
  "learn.stage2Desc": {
    en: "The prover extracts individual claims and the issuer's public key from the CBOR structure. Dates are converted to comparable values, strings become circuit inputs. The parser handles the mdoc DeviceSigned and IssuerSigned data elements as defined in ISO 18013-5.",
    uk: "Довідник витягує окремі поля та публічний ключ видавця з CBOR-структури. Дати конвертуються у порівнювані значення, рядки стають входами схеми. Парсер обробляє елементи DeviceSigned та IssuerSigned відповідно до ISO 18013-5.",
  },
  "learn.stage3Title": { en: "3. Prove", uk: "3. Доведення" },
  "learn.stage3Desc": {
    en: "Longfellow (Sumcheck + Ligero) generates a zero-knowledge proof. The COSE signature is verified natively inside the prover — no separate circuit needed. The proof demonstrates that a predicate holds (e.g., age >= 18) without revealing the underlying data. ~360 KB proof, ~1.2s prove + ~0.7s verify on server, no trusted setup required. The proving system is quantum-resistant: all commitments are hash-based, no pairing-based ceremony.",
    uk: "Longfellow (Sumcheck + Ligero) генерує доказ з нульовим знанням. Підпис COSE перевіряється нативно всередині довідника — без окремої схеми. Доказ демонструє, що предикат виконується (напр., вік >= 18) без розкриття вхідних даних. ~360 КБ доказ, ~1.2с генерація + ~0.7с верифікація на сервері, без довіреної ініціалізації. Система доведення квантово-стійка: всі зобов'язання базуються на хешах, без церемонії на основі пейрингів.",
  },
  "learn.stage3Nullifier": {
    en: "Each proof includes a nullifier — a deterministic hash that prevents double-use of the same credential for the same purpose, without revealing the holder's identity. Holder binding ties the proof to a specific device or session.",
    uk: "Кожен доказ включає нуліфікатор — детерміністичний хеш, що запобігає повторному використанню того ж посвідчення для тієї ж мети, без розкриття ідентичності власника. Прив'язка власника пов'язує доказ з конкретним пристроєм або сесією.",
  },
  "learn.stage3Predicates": {
    en: "Supported predicates: greater-than-or-equal (>=), less-than-or-equal (<=), equality (==), not-equal (!=), range (low <= x <= high), and set membership (x in {a, b, c}).",
    uk: "Підтримувані предикати: більше-або-дорівнює (>=), менше-або-дорівнює (<=), рівність (==), нерівність (!=), діапазон (low <= x <= high) та належність до множини (x in {a, b, c}).",
  },
  "learn.stage4Title": { en: "4. Store", uk: "4. Зберігання" },
  "learn.stage4Desc": {
    en: "The proof is content-addressed using SHA-256 and stored by its CID (Content Identifier). At ~360 KB, proofs are too large for QR codes (~3 KB max). The storage layer holds proofs until they are verified and attested. Future: IPFS pinning for decentralized storage.",
    uk: "Доказ адресується контентом через SHA-256 і зберігається за CID (ідентифікатором контенту). Розміром ~360 КБ, докази занадто великі для QR-кодів (~3 КБ макс). Рівень зберігання утримує докази до їх верифікації та атестації. Майбутнє: IPFS для децентралізованого зберігання.",
  },
  "learn.stage5Title": { en: "5. Attest", uk: "5. Атестація" },
  "learn.stage5Desc": {
    en: "A Qualified Trust Service Provider verifies the proof and issues a Qualified Electronic Attestation of Attributes (QEAA). The attestation is a W3C Verifiable Credential signed with ECDSA P-256. At ~1-2 KB, it fits in a single QR code. This is the key innovation: the attestation carries legal weight under eIDAS 2.0 Article 45d.",
    uk: "Кваліфікований довірений постачальник послуг перевіряє доказ і видає Кваліфіковану Електронну Атестацію Атрибутів (QEAA). Атестація — це W3C Verifiable Credential, підписаний ECDSA P-256. Розміром ~1-2 КБ, вона поміщається в один QR-код. Це ключова інновація: атестація має юридичну вагу за статтею 45d eIDAS 2.0.",
  },
  "learn.stage6Title": { en: "6. Verify", uk: "6. Верифікація" },
  "learn.stage6Desc": {
    en: "Two verification paths: (1) Full re-verification — fetch the proof by CID and re-run the Longfellow verifier. Trustless but requires connectivity. (2) Attestation check — verify the TSP's ECDSA signature on the QEAA. Fast, offline-capable, and legally binding. The QR code on a paper document carries the attestation.",
    uk: "Два шляхи верифікації: (1) Повна ре-верифікація — отримати доказ за CID і повторно запустити верифікатор Longfellow. Бездовірчо, але потребує з'єднання. (2) Перевірка атестації — перевірити підпис TSP (ECDSA) на QEAA. Швидко, працює офлайн, юридично зобов'язуюче. QR-код на паперовому документі містить атестацію.",
  },
  "learn.stage7Title": { en: "7. Escrow Opening", uk: "7. Розкриття ескроу" },
  "learn.stage7Desc": {
    en: "Identity escrow provides accountability without day-to-day surveillance. Credential fields are encrypted with AES-256-GCM. The symmetric key is encapsulated with ML-KEM-768 (post-quantum) to the TSP's public key. On court order or arbitration ruling, the TSP decrypts and reveals the holder's identity. Without a court order, the encrypted fields are meaningless — even the TSP cannot read them without the legal authorization to use its private key.",
    uk: "Ескроу ідентичності забезпечує підзвітність без повсякденного стеження. Поля посвідчення зашифровані AES-256-GCM. Симетричний ключ інкапсульований ML-KEM-768 (пост-квантовий) до публічного ключа TSP. За рішенням суду або арбітражу TSP дешифрує і розкриває ідентичність власника. Без рішення суду зашифровані поля безглузді — навіть TSP не може їх прочитати без юридичного дозволу на використання свого приватного ключа.",
  },
  "learn.tocStage1": { en: "Credential", uk: "Посвідчення" },
  "learn.tocStage2": { en: "Parse", uk: "Розбір" },
  "learn.tocStage3": { en: "Prove", uk: "Доведення" },
  "learn.tocStage4": { en: "Store", uk: "Зберігання" },
  "learn.tocStage5": { en: "Attest", uk: "Атестація" },
  "learn.tocStage6": { en: "Verify", uk: "Верифікація" },
  "learn.tocStage7": { en: "Escrow Opening", uk: "Розкриття ескроу" },

  // ── Stats ───────────────────────────────────────────────────────────────
  "stats.circuits": { en: "Longfellow Circuits", uk: "Longfellow схеми" },
  "stats.tests": { en: "Tests Passing", uk: "Тестів пройдено" },
  "stats.coverage": { en: "Code Coverage", uk: "Покриття коду" },
  "stats.crates": { en: "Rust Crates", uk: "Rust крейти" },
  "stats.license": { en: "License", uk: "Ліцензія" },

  // ── Footer ──────────────────────────────────────────────────────────────
  "footer.license": {
    en: "Open-source SDK for eIDAS 2.0 privacy. Apache 2.0.",
    uk: "SDK з відкритим кодом для приватності eIDAS 2.0. Apache 2.0.",
  },

  // ── Demo page ───────────────────────────────────────────────────────────
  "sandbox.subtitle": {
    en: "Zero-Knowledge Selective Disclosure for eIDAS 2.0 Credentials",
    uk: "Вибіркове розкриття з нульовим розголошенням для eIDAS 2.0 посвідчень",
  },
  "sandbox.step1Label": { en: "Issuer", uk: "Видавець" },
  "sandbox.step1Desc": { en: "Issue a verifiable credential", uk: "Видати верифіковане посвідчення" },
  "sandbox.step2Label": { en: "Schema", uk: "Схема" },
  "sandbox.step2Desc": { en: "Select predicates & generate proof", uk: "Обрати предикати та згенерувати доказ" },
  "sandbox.step3Label": { en: "Verifier", uk: "Верифікатор" },
  "sandbox.step3Desc": { en: "Zero-knowledge verification result", uk: "Результат верифікації з нульовим розголошенням" },
  "sandbox.step4Label": { en: "Print", uk: "Друк" },
  "sandbox.step4Desc": { en: "QR codes for offline verification", uk: "QR-коди для офлайн верифікації" },
  "sandbox.saveProof": { en: "Save Proof", uk: "Зберегти доказ" },

  // ── Tab labels ──────────────────────────────────────────────────────────
  "sandbox.tabPid": { en: "National ID (PID)", uk: "Національний ID (PID)" },
  "sandbox.tabDrivers": { en: "Driver\u2019s License", uk: "Водійське посвідчення" },
  "sandbox.tabDiploma": { en: "University Diploma", uk: "Диплом університету" },
  "sandbox.tabStudentId": { en: "Student Card", uk: "Студентський квиток" },
  "sandbox.tabVehicle": { en: "Vehicle Registration", uk: "Реєстрація ТЗ" },

  // ── Issuer titles per credential type ───────────────────────────────────
  "sandbox.issuerTitlePid": { en: "Credential Issuer \u2014 Diia", uk: "Видавець посвідчення \u2014 Дія" },
  "sandbox.issuerSubtitlePid": { en: "Ministry of Digital Transformation of Ukraine", uk: "Міністерство цифрової трансформації України" },
  "sandbox.issuerTitleDrivers": { en: "Credential Issuer \u2014 PPA", uk: "Видавець посвідчення \u2014 PPA" },
  "sandbox.issuerSubtitleDrivers": { en: "Police and Border Guard Board \u2014 Estonia", uk: "Поліцейсько-прикордонне управління \u2014 Естонія" },
  "sandbox.issuerTitleDiploma": { en: "Credential Issuer \u2014 Sorbonne Universit\u00e9", uk: "Видавець посвідчення \u2014 Сорбонна" },
  "sandbox.issuerSubtitleDiploma": { en: "Sorbonne Universit\u00e9 \u2014 France", uk: "Університет Сорбонни \u2014 Франція" },
  "sandbox.issuerTitleStudentId": { en: "Student Card Issuer \u2014 University of Warsaw", uk: "Видавець студентського квитка \u2014 Варшавський університет" },
  "sandbox.issuerSubtitleStudentId": { en: "Uniwersytet Warszawski \u2014 Poland", uk: "Uniwersytet Warszawski \u2014 Польща" },
  "sandbox.issuerTitleVehicle": { en: "Credential Issuer \u2014 KBA", uk: "Видавець посвідчення \u2014 KBA" },
  "sandbox.issuerSubtitleVehicle": { en: "Kraftfahrt-Bundesamt \u2014 Germany", uk: "Федеральне відомство автотранспорту \u2014 Німеччина" },
  "sandbox.issuerTitlePidDe": { en: "Bundesdruckerei", uk: "Bundesdruckerei" },
  "sandbox.issuerSubtitlePidDe": { en: "Federal Printing Office \u2014 Germany", uk: "Федеральна друкарня \u2014 Німеччина" },
  "sandbox.issuerTitleDriversUa": { en: "HSC MVS", uk: "ГСЦ МВС" },
  "sandbox.issuerSubtitleDriversUa": { en: "Main Service Centre of MIA \u2014 Ukraine", uk: "Головний сервісний центр МВС України" },
  "sandbox.issuerTitleStudentIdUa": { en: "Taras Shevchenko KNU", uk: "КНУ ім. Шевченка" },
  "sandbox.issuerSubtitleStudentIdUa": { en: "Taras Shevchenko National University \u2014 Ukraine", uk: "Київський національний університет ім. Тараса Шевченка" },
  "sandbox.issuerTitleDiplomaUa": { en: "Igor Sikorsky KPI", uk: "КПІ ім. Сікорського" },
  "sandbox.issuerSubtitleDiplomaUa": { en: "Igor Sikorsky Kyiv Polytechnic Institute \u2014 Ukraine", uk: "Київський політехнічний інститут ім. Ігоря Сікорського" },
  "sandbox.issuerTitleVehicleUa": { en: "MVS Ukraine", uk: "МВС України" },
  "sandbox.issuerSubtitleVehicleUa": { en: "Ministry of Internal Affairs \u2014 Ukraine", uk: "Міністерство внутрішніх справ України" },

  // ── Credential labels ──────────────────────────────────────────────────
  "sandbox.credLabelPid": { en: "Personal Identification Data (PID)", uk: "Персональні ідентифікаційні дані (PID)" },
  "sandbox.credLabelDrivers": { en: "EU Driver\u2019s License (mDL)", uk: "Водійське посвідчення ЄС (mDL)" },
  "sandbox.credLabelDiploma": { en: "University Diploma (EAA)", uk: "Диплом університету (EAA)" },
  "sandbox.credLabelStudentId": { en: "Student Card (EAA)", uk: "Студентський квиток (EAA)" },
  "sandbox.credLabelVehicle": { en: "Vehicle Registration Certificate", uk: "Свідоцтво про реєстрацію ТЗ" },

  // ── Field labels ───────────────────────────────────────────────────────
  "sandbox.fieldBirthDate": { en: "Date of Birth", uk: "Дата народження" },
  "sandbox.fieldAgeOver18": { en: "Age Over 18", uk: "Вік понад 18" },
  "sandbox.fieldIssuingCountry": { en: "Issuing Country", uk: "Країна видачі" },
  "sandbox.fieldGender": { en: "Gender", uk: "Стать" },
  "sandbox.fieldResidentCity": { en: "Resident City", uk: "Місто проживання" },
  "sandbox.fieldExpiryDate": { en: "Expiry Date", uk: "Дата закінчення" },
  "sandbox.predAgeOver18": { en: "Age confirmed (boolean)", uk: "Вік підтверджено (булеве)" },
  "sandbox.predAgeOver18Desc": { en: "Proves age_over_18 is true without revealing birthdate", uk: "Доводить, що age_over_18 є true без розкриття дати народження" },
  "sandbox.predIssuingCountry": { en: "Issuing country is in eIDAS zone", uk: "Країна видачі в зоні eIDAS" },
  "sandbox.predIssuingCountryDesc": { en: "Proves issuing country is an EU/eIDAS member", uk: "Доводить, що країна видачі є членом ЄС/eIDAS" },
  "sandbox.predDocValid": { en: "Document is not expired", uk: "Документ не прострочений" },
  "sandbox.predDocValidDesc": { en: "Proves expiry date is in the future", uk: "Доводить, що дата закінчення в майбутньому" },
  "sandbox.field.holderName": { en: "Holder Name", uk: "Ім'я власника" },
  "sandbox.field.category": { en: "Category", uk: "Категорія" },
  "sandbox.field.issueDate": { en: "Issue Date", uk: "Дата видачі" },
  "sandbox.field.expiryDate": { en: "Expiry Date", uk: "Дата закінчення" },
  "sandbox.field.restrictions": { en: "Restrictions", uk: "Обмеження" },
  "sandbox.field.licenseNumber": { en: "License Number", uk: "Номер посвідчення" },
  "sandbox.field.studentName": { en: "Student Name", uk: "Ім'я студента" },
  "sandbox.field.university": { en: "University", uk: "Університет" },
  "sandbox.field.degree": { en: "Degree", uk: "Ступінь" },
  "sandbox.field.fieldOfStudy": { en: "Field of Study", uk: "Спеціальність" },
  "sandbox.field.graduationYear": { en: "Graduation Year", uk: "Рік випуску" },
  "sandbox.field.diplomaNumber": { en: "Diploma Number", uk: "Номер диплома" },
  "sandbox.field.honors": { en: "Honors", uk: "Відзнака" },
  "sandbox.field.faculty": { en: "Faculty", uk: "Факультет" },
  "sandbox.field.enrollmentYear": { en: "Enrollment Year", uk: "Рік вступу" },
  "sandbox.field.validUntil": { en: "Valid Until", uk: "Дійсний до" },
  "sandbox.field.studentNumber": { en: "Student Number", uk: "Номер студентського квитка" },
  "sandbox.field.ownerName": { en: "Owner Name", uk: "Ім'я власника" },
  "sandbox.field.ownerDocNumber": { en: "Owner Document No.", uk: "Номер документа власника" },
  "sandbox.field.plateNumber": { en: "Plate Number", uk: "Номерний знак" },
  "sandbox.field.makeModel": { en: "Make & Model", uk: "Марка та модель" },
  "sandbox.field.vin": { en: "VIN", uk: "VIN" },
  "sandbox.field.insuranceExpiry": { en: "Insurance Expiry", uk: "Закінчення страховки" },
  "sandbox.field.registrationDate": { en: "Registration Date", uk: "Дата реєстрації" },

  // ── Predicate labels + descriptions ────────────────────────────────────
  "sandbox.predCategoryB": { en: "License includes category B", uk: "Посвідчення включає категорію B" },
  "sandbox.predCategoryBDesc": { en: "Proves category matches expected value", uk: "Доводить відповідність категорії очікуваному значенню" },
  "sandbox.predValid": { en: "License is valid (not expired)", uk: "Посвідчення дійсне (не прострочене)" },
  "sandbox.predValidDesc": { en: "Proves expiry date is in the future", uk: "Доводить, що дата закінчення в майбутньому" },
  "sandbox.predExperienced": { en: "Issued at least 2 years ago", uk: "Видано щонайменше 2 роки тому" },
  "sandbox.predExperiencedDesc": { en: "Proves driving experience of 2+ years", uk: "Доводить водійський досвід 2+ роки" },
  "sandbox.predNoRestrictions": { en: "No restrictions on license", uk: "Без обмежень на посвідченні" },
  "sandbox.predNoRestrictionsDesc": { en: "Proves restrictions field equals 'None'", uk: "Доводить, що поле обмежень дорівнює 'None'" },
  "sandbox.predStem": { en: "Field is in STEM", uk: "Спеціальність в STEM" },
  "sandbox.predStemDesc": { en: "Proves field of study is in STEM disciplines", uk: "Доводить, що спеціальність належить до STEM" },
  "sandbox.predRecentGrad": { en: "Graduated in 2020 or later", uk: "Закінчив у 2020 або пізніше" },
  "sandbox.predRecentGradDesc": { en: "Proves graduation year >= 2020", uk: "Доводить рік випуску >= 2020" },
  "sandbox.predMasters": { en: "Holds a Master's degree", uk: "Має ступінь магістра" },
  "sandbox.predMastersDesc": { en: "Proves degree is Master or PhD level", uk: "Доводить ступінь магістра або PhD" },
  "sandbox.predUniversityMatch": { en: "University matches value", uk: "Університет відповідає значенню" },
  "sandbox.predUniversityMatchDesc": { en: "Proves university equals expected value", uk: "Доводить, що університет дорівнює очікуваному" },
  "sandbox.predActiveStudent": { en: "Student card is valid", uk: "Студентський квиток дійсний" },
  "sandbox.predActiveStudentDesc": { en: "Proves the student card has not expired", uk: "Доводить, що студентський квиток не прострочений" },
  "sandbox.predEnrolledRecently": { en: "Enrolled in 2020 or later", uk: "Вступив у 2020 або пізніше" },
  "sandbox.predEnrolledRecentlyDesc": { en: "Proves enrollment year is 2020 or later", uk: "Доводить, що рік вступу — 2020 або пізніше" },
  "sandbox.predInsured": { en: "Vehicle is insured (not expired)", uk: "ТЗ застраховано (не прострочено)" },
  "sandbox.predInsuredDesc": { en: "Proves insurance expiry date is in the future", uk: "Доводить, що страховка не закінчилась" },
  "sandbox.predEuType": { en: "Make is EU type-approved", uk: "Марка сертифікована в ЄС" },
  "sandbox.predEuTypeDesc": { en: "Proves vehicle make is in EU type-approved list", uk: "Доводить, що марка авто в списку сертифікованих ЄС" },
  "sandbox.predVinActive": { en: "VIN not revoked", uk: "VIN не відкликано" },
  "sandbox.predVinActiveDesc": { en: "Proves VIN is not in revocation registry", uk: "Доводить, що VIN не в реєстрі відкликань" },

  "sandbox.issuerTitle": {
    en: "Credential Issuer \u2014 Diia",
    uk: "Видавець посвідчення \u2014 Дія",
  },
  "sandbox.issuerSubtitle": {
    en: "Ministry of Digital Transformation of Ukraine \u2014 PID Credential Example",
    uk: "Міністерство цифрової трансформації України \u2014 приклад PID посвідчення",
  },
  "sandbox.pidLabel": {
    en: "Personal Identification Data (PID) \u2014 one of many eIDAS 2.0 credential types",
    uk: "Персональні ідентифікаційні дані (PID) \u2014 один з багатьох типів eIDAS 2.0 посвідчень",
  },
  "sandbox.fieldGivenName": { en: "Given Name", uk: "Ім'я" },
  "sandbox.fieldFamilyName": { en: "Family Name", uk: "Прізвище" },
  "sandbox.fieldBirthdate": { en: "Date of Birth", uk: "Дата народження" },
  "sandbox.fieldNationality": { en: "Nationality", uk: "Громадянство" },
  "sandbox.fieldResidentCountry": {
    en: "Resident Country",
    uk: "Країна проживання",
  },
  "sandbox.fieldDocNumber": { en: "Document Number", uk: "Номер документа" },
  "sandbox.fieldIssuingAuthority": {
    en: "Issuing Authority",
    uk: "Орган видачі",
  },
  "sandbox.issuing": {
    en: "Issuing Credential...",
    uk: "Видача посвідчення...",
  },
  "sandbox.issueBtn": {
    en: "Issue Credential",
    uk: "Видати посвідчення",
  },
  "sandbox.issuingShort": { en: "Issuing...", uk: "Видача..." },
  "sandbox.pidCredential": { en: "PID Credential", uk: "PID посвідчення" },
  "sandbox.digitalCredential": {
    en: "Digital Credential",
    uk: "Цифрове посвідчення",
  },
  "sandbox.sdjwtVc": {
    en: "SD-JWT Verifiable Credential",
    uk: "SD-JWT верифіковане посвідчення",
  },
  "sandbox.sdjwtTooltip": {
    en: "A Selective Disclosure JSON Web Token. Each claim can be independently revealed or hidden.",
    uk: "Selective Disclosure JSON Web Token. Кожне твердження може бути незалежно розкрите або приховане.",
  },
  "sandbox.selectClaims": {
    en: "Select Claims to Prove",
    uk: "Оберіть дані для доведення",
  },
  "sandbox.selectClaimsSub": {
    en: "Choose predicates for zero-knowledge proof",
    uk: "Оберіть предикати для доказу з нульовим розголошенням",
  },
  "sandbox.predicateTooltip": {
    en: "A yes/no condition checked inside the ZK circuit, e.g. 'age >= 18'. The verifier learns only that the condition holds.",
    uk: "Умова так/ні, що перевіряється всередині ZK схеми, напр. 'вік >= 18'. Верифікатор дізнається лише, що умова виконана.",
  },
  "sandbox.predAge": {
    en: "I am at least 18 years old",
    uk: "Мені щонайменше 18 років",
  },
  "sandbox.predAgeDesc": {
    en: "Proves age >= 18 without revealing birthdate",
    uk: "Доводить вік >= 18 без розкриття дати народження",
  },
  "sandbox.predNat": {
    en: "My nationality is in the eIDAS zone",
    uk: "Моє громадянство — в зоні eIDAS",
  },
  "sandbox.predNatDesc": {
    en: "Proves eIDAS zone membership without revealing country",
    uk: "Доводить членство в зоні eIDAS без розкриття країни",
  },
  "sandbox.predName": {
    en: "My name matches a specific value",
    uk: "Моє ім'я збігається з конкретним значенням",
  },
  "sandbox.predNameDesc": {
    en: "Proves name equality without revealing it in plaintext",
    uk: "Доводить рівність імені без розкриття його у відкритому вигляді",
  },
  "sandbox.predAgeLte": {
    en: "I am at most 65 years old",
    uk: "Мені не більше 65 років",
  },
  "sandbox.predAgeLteDesc": {
    en: "Proves age <= 65 without revealing birthdate",
    uk: "Доводить вік <= 65 без розкриття дати народження",
  },
  "sandbox.predNotRevoked": {
    en: "My credential is not revoked",
    uk: "Моє посвідчення не відкликане",
  },
  "sandbox.predNotRevokedDesc": {
    en: 'Proves document number is not "REVOKED"',
    uk: 'Доводить, що номер документа не "REVOKED"',
  },
  "sandbox.predAgeRange": {
    en: "My age is between 18 and 65",
    uk: "Мій вік від 18 до 65 років",
  },
  "sandbox.predAgeRangeDesc": {
    en: "Proves age is between 18 and 65 in a single circuit",
    uk: "Доводить, що вік від 18 до 65 в одній схемі",
  },
  "sandbox.proofMode": { en: "Proof Mode", uk: "Режим доказу" },
  "sandbox.proofModeTooltip": {
    en: "Individual proofs are verified separately. Compound proofs combine multiple predicates with AND/OR logic into a single proof.",
    uk: "Індивідуальні докази перевіряються окремо. Складені докази об'єднують кілька предикатів за логікою AND/OR в один доказ.",
  },
  "sandbox.modeIndividual": { en: "Individual", uk: "Індивідуальний" },
  "sandbox.modeIndividualDesc": {
    en: "Separate proof per predicate",
    uk: "Окремий доказ на предикат",
  },
  "sandbox.modeAndDesc": { en: "All must hold", uk: "Усі мають виконуватись" },
  "sandbox.modeOrDesc": {
    en: "At least one must hold",
    uk: "Щонайменше один має виконуватись",
  },
  "sandbox.modeExplainIndividual": {
    en: "Each predicate generates a separate proof",
    uk: "Кожен предикат генерує окремий доказ",
  },
  "sandbox.modeExplainAnd": {
    en: "Single compound proof \u2014 ALL predicates must be true",
    uk: "Один складений доказ \u2014 УСІ предикати мають бути істинними",
  },
  "sandbox.modeExplainDocNumber": {
    en: "Locked to AND \u2014 document number binds all predicates to one credential.",
    uk: "Зафіксовано AND \u2014 номер документа прив'язує всі предикати до одного посвідчення.",
  },
  "sandbox.modeUnlock": {
    en: "Disable document disclosure to unlock.",
    uk: "Вимкніть розкриття документа для розблокування.",
  },
  "sandbox.printRequiresAnd": {
    en: "Paper proofs require AND mode with document number disclosure for holder binding.",
    uk: "Паперові докази потребують режим AND з розкриттям номера документа для прив'язки до власника.",
  },
  "sandbox.modeExplainOr": {
    en: "Single compound proof \u2014 AT LEAST ONE predicate must be true",
    uk: "Один складений доказ \u2014 ЩОНАЙМЕНШЕ ОДИН предикат має бути істинним",
  },
  "sandbox.nullifierScope": {
    en: "Nullifier Scope",
    uk: "Скоп нуліфікатора",
  },
  "sandbox.nullifierTooltip": {
    en: "A deterministic hash scoped to a context. Same credential + same scope = same nullifier, enabling double-spend detection.",
    uk: "Детермінований хеш, прив'язаний до контексту. Те саме посвідчення + той самий скоп = той самий нуліфікатор, що дозволяє виявити подвійне використання.",
  },
  "sandbox.optional": { en: "(optional)", uk: "(необов'язково)" },
  "sandbox.discloseDocNumber": {
    en: "Disclose document number",
    uk: "Розкрити номер документа",
  },
  "sandbox.discloseDocNumberDesc": {
    en: "Include the document number in plaintext so the verifier can cross-reference it against a physical ID. Recommended for paper proofs.",
    uk: "Включити номер документа у відкритому вигляді, щоб верифікатор міг звірити його з фізичним документом. Рекомендовано для паперових доказів.",
  },
  "sandbox.docNumberWarning": {
    en: "Without a disclosed document number, a paper proof cannot be tied to a specific person. The verifier will have no way to confirm who the credential belongs to.",
    uk: "Без розкритого номера документа паперовий доказ не може бути прив'язаний до конкретної особи. Верифікатор не зможе підтвердити, кому належить посвідчення.",
  },
  "sandbox.disclosed": {
    en: "disclosed",
    uk: "розкрито",
  },
  "sandbox.nullifierDesc": {
    en: "Generates a deterministic nullifier for double-spend detection. Same scope = same nullifier.",
    uk: "Генерує детермінований нуліфікатор для виявлення подвійного використання. Той самий скоп = той самий нуліфікатор.",
  },
  "sandbox.generating": {
    en: "Generating cryptographic proof... ",
    uk: "Генерація криптографічного доказу... ",
  },
  "sandbox.generatingDesc": {
    en: "Real ECDSA signature verification + zero-knowledge circuit execution in progress",
    uk: "Реальна перевірка ECDSA підпису + виконання схеми з нульовим розголошенням",
  },
  "sandbox.proofGenerated": {
    en: "Proof generated successfully",
    uk: "Доказ успішно згенеровано",
  },
  "sandbox.backToIssuer": {
    en: "\u2190 Back to Issuer",
    uk: "\u2190 Назад до видавця",
  },
  "sandbox.generatingShort": { en: "Generating...", uk: "Генерація..." },
  "sandbox.proofGeneratedBtn": {
    en: "Proof Generated",
    uk: "Доказ згенеровано",
  },
  "sandbox.generateBtn": {
    en: "Generate ZK Proof",
    uk: "Згенерувати доказ з НР",
  },
  "sandbox.verifierTitle": {
    en: "Service Provider \u2014 Verification Portal",
    uk: "Постачальник послуг \u2014 Портал верифікації",
  },
  "sandbox.verifierSubtitle": {
    en: "Zero-Knowledge Proof Verification",
    uk: "Верифікація доказу з нульовим розголошенням",
  },
  "sandbox.receivedArtifact": {
    en: "Received Proof Artifact",
    uk: "Отриманий артефакт доказу",
  },
  "sandbox.opaqueNote": {
    en: "Opaque cryptographic artifact \u2014 no credential data visible to verifier",
    uk: "Непрозорий криптографічний артефакт \u2014 дані посвідчення не видимі верифікатору",
  },
  "sandbox.verifyServer": {
    en: "Verify on Server",
    uk: "Перевірити на сервері",
  },
  "sandbox.verifyServerBoring": {
    en: "or verify on server, if you\u2019re old school",
    uk: "або перевірити на сервері, якщо ви старої школи",
  },
  "sandbox.verifyingShort": { en: "Verifying...", uk: "Перевірка..." },
  "sandbox.autoVerifying": { en: "Verifying proof...", uk: "Верифікація доказу..." },
  "sandbox.verificationResults": {
    en: "Verification Results",
    uk: "Результати верифікації",
  },
  "sandbox.verifiedServer": {
    en: "Verified server-side",
    uk: "Перевірено на сервері",
  },
  "sandbox.verifiedServerTooltip": {
    en: "Proof verified on the server using Longfellow (Sumcheck+Ligero). No trusted setup required.",
    uk: "Доказ перевірено на сервері за допомогою Longfellow (Sumcheck+Ligero). Довірена ініціалізація не потрібна.",
  },
  "sandbox.verified": { en: "Verified", uk: "Перевірено" },
  "sandbox.notDisclosed": { en: "Not Disclosed", uk: "Не розкрито" },
  "sandbox.nullifierChecking": {
    en: "Checking nullifier registry...",
    uk: "Перевірка реєстру нуліфікаторів...",
  },
  "sandbox.doubleSpend": {
    en: "DOUBLE-SPEND DETECTED \u2014 This proof was already used",
    uk: "ВИЯВЛЕНО ПОДВІЙНЕ ВИКОРИСТАННЯ \u2014 Цей доказ вже був використаний",
  },
  "sandbox.firstUse": {
    en: "First use \u2014 Nullifier registered",
    uk: "Перше використання \u2014 Нуліфікатор зареєстровано",
  },
  "sandbox.registryCount": { en: "recorded", uk: "записано" },
  "sandbox.privacyBanner": {
    en: "The verifier learned NOTHING about the credential holder — only the document number (as a public anchor) and that these predicates are true.",
    uk: "Верифікатор не дізнався НІЧОГО про власника посвідчення — лише номер документа (як публічний ідентифікатор) та що ці предикати істинні.",
  },
  "sandbox.zkTitle": {
    en: "How it works: from your data to a proof",
    uk: "Як це працює: від ваших даних до доказу",
  },
  "sandbox.zkSubtitle": {
    en: "Your personal data never leaves your device. Only a mathematical proof is shared.",
    uk: "Ваші персональні дані ніколи не покидають ваш пристрій. Передається лише математичний доказ.",
  },
  "sandbox.zkStep1Title": {
    en: "Your ID document",
    uk: "Ваш документ",
  },
  "sandbox.zkStep1Desc": {
    en: "This data is private. Only you can see it.",
    uk: "Ці дані приватні. Бачите їх лише ви.",
  },
  "sandbox.zkStep2Title": {
    en: "Each question is checked, then the data is destroyed",
    uk: "Кожне питання перевіряється, а потім дані знищуються",
  },
  "sandbox.zkStep2Desc": {
    en: "A program reads your real value, checks if the condition is true, and outputs only \u201Cyes\u201D or \u201Cno\u201D. The actual value is never stored or sent anywhere.",
    uk: "Програма зчитує ваше реальне значення, перевіряє чи умова істинна, і видає лише \u201Cтак\u201D або \u201Cні\u201D. Фактичне значення ніколи не зберігається і нікуди не відправляється.",
  },
  "sandbox.zkRealValue": { en: "real value", uk: "реальне значення" },
  "sandbox.zkOnlyAnswer": { en: "only yes/no leaves", uk: "виходить лише так/ні" },
  "sandbox.zkStep2Note": {
    en: "The government\u2019s digital signature is checked inside the proof, so nobody can fake the answer.",
    uk: "Цифровий підпис уряду перевіряється всередині доказу, тому ніхто не може підробити відповідь.",
  },
  "sandbox.zkStep3Title": {
    en: "What the verifier actually receives",
    uk: "Що насправді отримує верифікатор",
  },
  "sandbox.zkStep3Desc": {
    en: "Only the proven facts. Everything else is invisible.",
    uk: "Лише доведені факти. Все інше невидиме.",
  },
  "sandbox.proofExport": { en: "Proof Export", uk: "Експорт доказу" },
  "sandbox.cborTooltip": {
    en: "Concise Binary Object Representation. A compact binary format for portable proof envelopes.",
    uk: "Concise Binary Object Representation. Компактний бінарний формат для портативних конвертів доказів.",
  },
  "sandbox.cborBinaryTooltip": {
    en: "Downloads the proof as a CBOR binary file — portable, offline-verifiable.",
    uk: "Завантажує доказ як бінарний CBOR файл — портативний, верифікується офлайн.",
  },
  "sandbox.encoding": { en: "Encoding...", uk: "Кодування..." },
  "sandbox.exportCbor": { en: "Export as CBOR", uk: "Експортувати як CBOR" },
  "sandbox.exportCompoundCbor": { en: "Export Compound Proof as CBOR", uk: "Експортувати складений доказ у CBOR" },
  "sandbox.cborDesc": {
    en: "CBOR-encoded proof envelope. Portable binary format for offline verification.",
    uk: "Конверт доказу в форматі CBOR. Портативний бінарний формат для офлайн верифікації.",
  },
  "sandbox.downloadCbor": { en: "Download .cbor", uk: "Завантажити .cbor" },
  "sandbox.saveCbor": { en: "Save .cbor", uk: "Зберегти .cbor" },
  "sandbox.printProof": { en: "Generate Certificate", uk: "Сформувати засвідчення" },
  "sandbox.revocationTitle": {
    en: "Credential Revocation",
    uk: "Відкликання посвідчення",
  },
  "sandbox.revoked": { en: "Revoked", uk: "Відкликано" },
  "sandbox.revokeDesc": {
    en: "Issuer can revoke credential using the Sparse Merkle Tree registry.",
    uk: "Видавець може відкликати посвідчення за допомогою реєстру розрідженого дерева Меркла.",
  },
  "sandbox.revokeTooltip": {
    en: "Adds the credential ID to the Sparse Merkle Tree revocation registry. After revocation, proofs using this credential will fail the revocation check.",
    uk: "Додає ID посвідчення до реєстру відкликань на основі розрідженого дерева Меркла. Після відкликання докази з цим посвідченням не пройдуть перевірку.",
  },
  "sandbox.revoking": { en: "Revoking...", uk: "Відкликання..." },
  "sandbox.revokeBtn": {
    en: "Revoke This Credential",
    uk: "Відкликати це посвідчення",
  },
  "sandbox.credentialRevoked": {
    en: "Credential revoked",
    uk: "Посвідчення відкликано",
  },
  "sandbox.revocationRoot": {
    en: "Revocation Root (SMT)",
    uk: "Корінь відкликання (SMT)",
  },
  "sandbox.currentRevRoot": {
    en: "Current Revocation Root",
    uk: "Поточний корінь відкликання",
  },
  "sandbox.fetchingRoot": {
    en: "Fetching...",
    uk: "Завантаження...",
  },
  "sandbox.openid4vpTitle": {
    en: "OpenID4VP Presentation Request",
    uk: "OpenID4VP запит презентації",
  },
  "sandbox.openid4vpDesc": {
    en: "Generate an OpenID4VP-compatible PresentationDefinition that wallets can consume.",
    uk: "Згенерувати PresentationDefinition, сумісний з OpenID4VP, який гаманці можуть обробити.",
  },
  "sandbox.openid4vpGenerating": { en: "Generating...", uk: "Генерація..." },
  "sandbox.openid4vpBtn": {
    en: "Generate Presentation Request",
    uk: "Згенерувати запит презентації",
  },
  "sandbox.presReqAddReq": { en: "Add Requirement", uk: "Додати вимогу" },
  "sandbox.presReqRemove": { en: "Remove", uk: "Видалити" },
  "sandbox.presReqClaim": { en: "Claim", uk: "Поле" },
  "sandbox.presReqOp": { en: "Operation", uk: "Операція" },
  "sandbox.presReqValue": { en: "Value", uk: "Значення" },
  "sandbox.presReqEmpty": { en: "Add at least one requirement", uk: "Додайте хоча б одну вимогу" },
  "sandbox.startOver": { en: "Start Over", uk: "Почати спочатку" },

  // ── Credential showcase (landing) ────────────────────────────────────────
  "cred.pid": { en: "Personal Identification Data", uk: "Персональні ідентифікаційні дані" },
  "cred.name": { en: "Name", uk: "Ім'я" },
  "cred.birthdate": { en: "Birthdate", uk: "Дата народж." },
  "cred.nationality": { en: "Nationality", uk: "Громад." },
  "cred.document": { en: "Document", uk: "Документ" },
  "cred.authority": { en: "Authority", uk: "Орган" },
  "cred.hidden": { en: "hidden", uk: "приховано" },
  "cred.zkVerified": { en: "ZK Verified", uk: "ZK Верифіковано" },
  "cred.conditions": {
    en: "Conditions: \u2713 age \u2265 18 | \u2713 vehicle owner",
    uk: "Умови: \u2713 вік \u2265 18 | \u2713 власник ТЗ",
  },
  "cred.nullifier": {
    en: "Nullifier: 0x8a3f\u2026e721",
    uk: "Нуліфікатор: 0x8a3f\u2026e721",
  },
  "cred.noPersonalData": {
    en: "Personal data: none",
    uk: "Персональні дані: жодних",
  },
  "cred.revoke": { en: "Revoke", uk: "Відкликати" },
  "cred.sigLine": { en: "sig: secp256r1 verified in-circuit", uk: "secp256r1 в схемі" },
  "cred.proofSize": { en: "ZK proof: ~360 KB (QEAA attestation: ~1-2 KB)", uk: "ZK доказ: ~360 КБ (QEAA атестація: ~1-2 КБ)" },
  "cred.tagline": { en: "Any eIDAS 2.0 credential \u2014 selective disclosure without compromise", uk: "Будь-яке eIDAS 2.0 посвідчення \u2014 вибіркове розкриття без компромісів" },

  // ── Credential showcase: document type labels ──────────────────────────
  "cred.driverLicense": { en: "Driver\u2019s License", uk: "Водійське посвідчення" },
  "cred.category": { en: "Category", uk: "Категорія" },
  "cred.issueDate": { en: "Issued", uk: "Видано" },
  "cred.expiryDate": { en: "Expires", uk: "Дійсне до" },
  "cred.restrictions": { en: "Restrictions", uk: "Обмеження" },

  "cred.diploma": { en: "University Diploma", uk: "Диплом університету" },
  "cred.university": { en: "University", uk: "Університет" },
  "cred.degree": { en: "Degree", uk: "Ступінь" },
  "cred.field": { en: "Field", uk: "Спеціальність" },
  "cred.gradYear": { en: "Graduated", uk: "Рік випуску" },
  "cred.honors": { en: "Honors", uk: "Відзнака" },

  "cred.vehicleReg": { en: "Vehicle Registration", uk: "Реєстрація ТЗ" },
  "cred.plate": { en: "Plate", uk: "Номер" },
  "cred.make": { en: "Make", uk: "Марка" },
  "cred.vin": { en: "VIN", uk: "VIN" },
  "cred.insurance": { en: "Insured", uk: "Застраховано" },
  "cred.owner": { en: "Owner", uk: "Власник" },

  // ── Verify page ─────────────────────────────────────────────────────────
  "verify.title": {
    en: "Offline Proof Verifier",
    uk: "Офлайн верифікатор доказів",
  },
  "verify.subtitle": {
    en: "Scan a QEAA attestation QR code or drop a .cbor proof envelope to verify. Attestations are verified offline via TSP signature; full proofs are verified server-side.",
    uk: "Скануйте QR-код QEAA атестації або перетягніть .cbor конверт доказу для верифікації. Атестації перевіряються офлайн через підпис TSP; повні докази перевіряються на сервері.",
  },
  "verify.offlineVerifier": {
    en: "Offline Verifier",
    uk: "Офлайн верифікатор",
  },
  "verify.pwaTip": {
    en: "Works offline.",
    uk: "Працює офлайн.",
  },
  "verify.pwaDesc": {
    en: "Add this page to your home screen to install it as an app. Scan QEAA attestation QR codes and verify them offline via TSP signature check.",
    uk: "Додайте цю сторінку на головний екран, щоб встановити як застосунок. Скануйте QR-коди QEAA атестацій та перевіряйте їх офлайн через перевірку підпису TSP.",
  },
  "verify.dropHere": {
    en: "Drop a .cbor proof file here",
    uk: "Перетягніть .cbor файл доказу сюди",
  },
  "verify.orBrowse": {
    en: "or click to browse",
    uk: "або натисніть для вибору",
  },
  "verify.proofEnvelope": { en: "Proof Envelope", uk: "Конверт доказу" },
  "verify.verifyAllWasm": {
    en: "Verify All",
    uk: "Перевірити все",
  },
  "verify.verifyingBrowser": {
    en: "Verifying...",
    uk: "Перевірка...",
  },
  "verify.allVerified": {
    en: "All proofs verified successfully.",
    uk: "Всі докази успішно перевірено.",
  },
  "verify.vkNote": {
    en: "Proofs verified via Longfellow (Sumcheck+Ligero). Attestations verified via TSP signature.",
    uk: "Докази перевірено через Longfellow (Sumcheck+Ligero). Атестації перевірено через підпис TSP.",
  },
  "verify.verifyAnother": {
    en: "Verify Another File",
    uk: "Перевірити інший файл",
  },
  "verify.valid": { en: "VALID", uk: "ВАЛІДНИЙ" },
  "verify.invalid": { en: "INVALID", uk: "НЕВАЛІДНИЙ" },
  "verify.scanPaper": {
    en: "Scan Paper Proof",
    uk: "Сканувати паперовий доказ",
  },
  "verify.scanning": {
    en: "Point camera at QR codes...",
    uk: "Наведіть камеру на QR-коди...",
  },
  "verify.scanProgress": {
    en: "chunks scanned",
    uk: "частин відскановано",
  },
  "verify.scanComplete": {
    en: "All chunks collected. Verifying...",
    uk: "Всі частини зібрано. Верифікація...",
  },
  "verify.cameraError": {
    en: "Camera access denied. Use file upload instead.",
    uk: "Доступ до камери заборонено. Використайте завантаження файлу.",
  },
  "verify.stopScanning": {
    en: "Stop Scanning",
    uk: "Зупинити сканування",
  },
  "verify.orScanPaper": {
    en: "or scan a printed proof",
    uk: "або скануйте друкований доказ",
  },
  "verify.chainVerified": {
    en: "ECDSA \u2192 commitment chain verified",
    uk: "Ланцюг ECDSA \u2192 commitment перевірено",
  },
  "verify.chainFailed": {
    en: "Commitment chain mismatch",
    uk: "Невідповідність ланцюга commitment",
  },
  "verify.scanOverall": {
    en: "Scanned {n} of {total} QR codes",
    uk: "Зіскановано {n} з {total} QR-кодів",
  },
  "verify.contractIntegrity": {
    en: "CONTRACT INTEGRITY",
    uk: "ЦІЛІСНІСТЬ КОНТРАКТУ",
  },
  "verify.hashMatch": {
    en: "contract_hash matches SHA256(terms \u2225 timestamp)",
    uk: "contract_hash збігається з SHA256(умови \u2225 мітка часу)",
  },
  "verify.hashMismatch": {
    en: "Contract hash does not match terms content. Document may be tampered.",
    uk: "Хеш контракту не збігається зі змістом умов. Документ міг бути підроблений.",
  },
  "verify.parties": {
    en: "PARTIES",
    uk: "СТОРОНИ",
  },
  "verify.verifyParty": {
    en: "MATCH NULLIFIER TO PARTY",
    uk: "ЗІСТАВИТИ НУЛІФІКАТОР ЗІ СТОРОНОЮ",
  },
  "verify.documentNumber": {
    en: "Nullifier hash (from proof receipt)",
    uk: "Хеш нуліфікатора (з квитанції доказу)",
  },
  "verify.check": {
    en: "Check",
    uk: "Перевірити",
  },
  "verify.partyMatch": {
    en: "Match: {role} nullifier",
    uk: "Збіг: нуліфікатор {role}",
  },
  "verify.noMatch": {
    en: "No party in this document matches this credential.",
    uk: "Жодна сторона в цьому документі не відповідає цьому посвідченню.",
  },
  "verify.termsQr": {
    en: "Contract terms",
    uk: "Умови контракту",
  },
  "verify.metadataQr": {
    en: "Contract metadata",
    uk: "Метадані контракту",
  },
  "verify.proofN": {
    en: "Proof {n}",
    uk: "Доказ {n}",
  },

  "verify.escrowDetected": {
    en: "Identity Escrow Envelopes Detected",
    uk: "Виявлено ескроу-конверти ідентичності",
  },
  "verify.escrowAuthority": {
    en: "Authority",
    uk: "Авторитет",
  },
  "verify.escrowFingerprint": {
    en: "Fingerprint",
    uk: "Відбиток",
  },
  "verify.escrowDecrypt": {
    en: "Decrypt (paste authority seed)",
    uk: "Розшифрувати (вставте сід авторитету)",
  },
  "verify.escrowSeedPlaceholder": {
    en: "Authority seed (hex)",
    uk: "Сід авторитету (hex)",
  },
  "verify.escrowDecrypted": {
    en: "Decrypted Identity",
    uk: "Розшифрована особа",
  },
  "verify.escrowIntegrityValid": {
    en: "Integrity verified — hash matches",
    uk: "Цілісність перевірена — хеш збігається",
  },
  "verify.escrowIntegrityFail": {
    en: "Integrity check failed — hash mismatch",
    uk: "Перевірку цілісності не пройдено — хеш не збігається",
  },

  // ── Print page ──────────────────────────────────────────────────────────
  "print.title": {
    en: "Zero-Knowledge Attestation",
    uk: "Засвідчення з нульовим розголошенням",
  },
  "print.scanToVerify": {
    en: "Scan all QR codes to verify",
    uk: "Скануйте всі QR-коди для верифікації",
  },
  "print.verifyAt": {
    en: "Verify at",
    uk: "Верифікація на",
  },
  "print.allMustVerify": {
    en: "ALL proofs must verify",
    uk: "УСІ докази мають пройти верифікацію",
  },
  "print.anyMustVerify": {
    en: "ANY one proof must verify",
    uk: "БУДЬ-ЯКИЙ один доказ має пройти верифікацію",
  },
  "print.proofSection": {
    en: "Proof",
    uk: "Доказ",
  },
  "print.printBtn": {
    en: "Print Proof",
    uk: "Друкувати доказ",
  },
  "print.generating": {
    en: "Generating QR codes...",
    uk: "Генерація QR-кодів...",
  },
  "print.compoundProof": { en: "Compound proof", uk: "Складений доказ" },
  "print.predicates": { en: "Proven predicates", uk: "Доведені предикати" },
  "print.qrCount": { en: "QR codes", uk: "QR-кодів" },
  "print.page": { en: "Page", uk: "Сторінка" },
  "print.public": { en: "public", uk: "публічний" },
  "print.private": { en: "private", uk: "приватний" },
  "print.claim": { en: "Claim", uk: "Поле" },
  "print.input": { en: "Input", uk: "Вхідне значення" },

  "nav.contracts": { en: "Demo", uk: "Демо" },

  // ── Contracts ──────────────────────────────────────────────────────────
  "contracts.title": { en: "Contract Wizard", uk: "Майстер договорів" },
  "contracts.subtitle": { en: "Zero-knowledge contract verification", uk: "Верифікація договорів з нульовим розголошенням" },
  "contracts.step1Label": { en: "Template", uk: "Шаблон" },
  "contracts.step1Desc": { en: "Choose a contract template", uk: "Оберіть шаблон договору" },
  "contracts.step2Label": { en: "Credential", uk: "Посвідчення" },
  "contracts.step2Desc": { en: "Issue the required credential", uk: "Видати необхідне посвідчення" },
  "contracts.step3Label": { en: "Prove", uk: "Доказ" },
  "contracts.step3Desc": { en: "Generate zero-knowledge proof", uk: "Згенерувати доказ з нульовим розголошенням" },
  "contracts.step4Label": { en: "Document", uk: "Документ" },
  "contracts.step4Desc": { en: "Preview and print the contract", uk: "Перегляд та друк договору" },
  "contracts.step5Label": { en: "Verify", uk: "Перевірка" },
  "contracts.step5Desc": { en: "Verify the zero-knowledge proof", uk: "Перевірити доказ з нульовим розголошенням" },
  "contracts.startOver": { en: "Start Over", uk: "Почати спочатку" },
  "contracts.credentialSingular": { en: "credential", uk: "посвідчення" },
  "contracts.credentialPlural": { en: "credentials", uk: "посвідчень" },
  "contracts.proofs": { en: "proofs", uk: "доказів" },
  "contracts.binding.count": { en: "binding", uk: "зв'язок" },
  "contracts.generateProof": { en: "Generate Proof", uk: "Згенерувати доказ" },
  "contracts.cachedNotice": { en: "Cached proof — generate a real one", uk: "Кешований доказ — згенерувати справжній" },
  "contracts.verifyDocument": { en: "Verify", uk: "Перевірити" },
  "contracts.print": { en: "Print", uk: "Друкувати" },
  "contracts.party1": { en: "Party 1", uk: "Особа 1" },
  "contracts.disclosed": { en: "public", uk: "публічний" },
  "contracts.signatureLine": { en: "Signature", uk: "Підпис" },
  "contracts.predicatesProved": { en: "Predicates proved", uk: "Доведені предикати" },
  "contracts.documentId": { en: "Document ID (disclosed)", uk: "ID документа (розкритий)" },
  "contracts.nullifier": { en: "Nullifier", uk: "Нуліфікатор" },
  "contracts.contractHash": { en: "Contract Hash", uk: "Хеш контракту" },
  "contracts.salt": { en: "Salt", uk: "Сіль" },
  "contracts.nullifierTooltip": { en: "This nullifier uniquely identifies your participation in this contract. It cannot be linked to you or any other contract. Only the credential issuer can resolve it to your identity under a court order.", uk: "Цей нуліфікатор унікально ідентифікує вашу участь у цьому контракті. Його неможливо пов'язати з вами чи іншим контрактом. Тільки видавець посвідчення може розкрити вашу особу за рішенням суду." },
  "contracts.shared": { en: "SHARED", uk: "СПІЛЬНЕ" },
  "contracts.issuer": { en: "Issuer", uk: "Видавець" },
  "contracts.date": { en: "Date", uk: "Дата" },
  "contracts.role.holder": { en: "Holder", uk: "Власник" },
  "contracts.role.student": { en: "Student Card", uk: "Студентський квиток" },
  "contracts.role.studentPid": { en: "Personal ID (age proof)", uk: "Посвідчення особи (підтвердження віку)" },
  "contracts.role.driver": { en: "Driver", uk: "Водій" },
  "contracts.role.seller": { en: "Seller ID", uk: "Посвідчення продавця" },
  "contracts.role.buyer": { en: "Buyer ID", uk: "Посвідчення покупця" },
  "contracts.role.vehicleReg": { en: "Vehicle Registration", uk: "Реєстрація ТЗ" },
  "contracts.credentialOf": { en: "Credential", uk: "Посвідчення" },
  "contracts.binding.sellerOwnsVehicle": { en: "Seller identity matches vehicle owner", uk: "Особа продавця відповідає власнику ТЗ" },
  "contracts.binding.verified": { en: "Holder binding verified", uk: "Зв'язок власника підтверджено" },
  "contracts.binding.hashMatch": { en: "Binding hash match", uk: "Збіг хешу зв'язку" },
  "contracts.binding.proving": { en: "Proving holder binding…", uk: "Доведення зв'язку власника…" },
  "contracts.dismiss": { en: "Dismiss", uk: "Закрити" },
  "contracts.generating": { en: "Generating proof…", uk: "Генерація доказу…" },
  "contracts.credential": { en: "credential", uk: "посвідчення" },
  "contracts.binding": { en: "verifying binding…", uk: "перевірка зв'язку…" },
  "contracts.contractText": { en: "Contract Text", uk: "Текст договору" },
  "contracts.contractTextHint": { en: "This text is hashed into the contract — edit freely. Salt ensures uniqueness.", uk: "Цей текст хешується в контракт — редагуйте вільно. Сіль забезпечує унікальність." },
  "contracts.verifying": { en: "Verifying…", uk: "Перевірка…" },
  "contracts.verified": { en: "All predicates verified", uk: "Всі предикати перевірені" },
  "contracts.verifyFailed": { en: "Verification failed", uk: "Перевірка не вдалася" },
  "contracts.ecdsaVerification": { en: "ECDSA Signature Verification", uk: "Верифікація підпису ECDSA" },
  "contracts.chainValid": { en: "Commitment chain verified", uk: "Ланцюг комітментів перевірено" },
  "contracts.chainBroken": { en: "Commitment chain broken", uk: "Ланцюг комітментів порушено" },
  "contracts.chainDesc": { en: "ECDSA signature \u2192 commitment \u2192 predicate: same data throughout", uk: "Підпис ECDSA \u2192 комітмент \u2192 предикат: ті самі дані наскрізь" },
  "contracts.escrowProofValid": { en: "Escrow encryption proof verified", uk: "Доказ ескроу-шифрування перевірено" },
  "contracts.escrowProofFail": { en: "Escrow encryption proof failed", uk: "Доказ ескроу-шифрування не пройшов" },
  "contracts.escrowProofDesc": { en: "ZK proof that encrypted data matches the signed credential", uk: "ZK-доказ, що зашифровані дані відповідають підписаному посвідченню" },
  "contracts.integrityValid": { en: "Integrity verified \u2014 hash matches", uk: "Цілісність перевірена \u2014 хеш збігається" },
  "contracts.integrityFail": { en: "Integrity check failed \u2014 hash mismatch", uk: "Перевірка цілісності не пройшла \u2014 хеш не збігається" },
  "contracts.ageVerification.title": { en: "Age Verification", uk: "Перевірка віку" },
  "contracts.ageVerification.desc": { en: "Prove you are 18+ without revealing your birthdate", uk: "Доведіть, що вам 18+ без розкриття дати народження" },
  "contracts.ageVerification.body_en": { en: "Party 1 (\"the Holder\") has cryptographically proven that they are at least 18 years of age. No name, birthdate, address, or other personal data has been disclosed. The verifier knows only that the age condition is satisfied and that the proof is bound to a government-issued credential via its document ID.\n\nThis contract requires no personal information to be valid. The zero-knowledge proof replaces traditional identity disclosure.", uk: "Party 1 (\"the Holder\") has cryptographically proven that they are at least 18 years of age. No name, birthdate, address, or other personal data has been disclosed. The verifier knows only that the age condition is satisfied and that the proof is bound to a government-issued credential via its document ID.\n\nThis contract requires no personal information to be valid. The zero-knowledge proof replaces traditional identity disclosure." },
  "contracts.ageVerification.body_uk": { en: "Особа 1 (\"Власник\") криптографічно довела, що їй щонайменше 18 років. Ім'я, дата народження, адреса та інші персональні дані не розкриті. Верифікатор знає лише, що умова віку виконана, а доказ прив'язаний до державного посвідчення через його ID.\n\nЦей договір не потребує персональних даних для чинності. Доказ з нульовим розголошенням замінює традиційне розкриття особи.", uk: "Особа 1 (\"Власник\") криптографічно довела, що їй щонайменше 18 років. Ім'я, дата народження, адреса та інші персональні дані не розкриті. Верифікатор знає лише, що умова віку виконана, а доказ прив'язаний до державного посвідчення через його ID.\n\nЦей договір не потребує персональних даних для чинності. Доказ з нульовим розголошенням замінює традиційне розкриття особи." },
  "contracts.studentTransit.title": { en: "Student Transit Pass", uk: "Студентський проїзний" },
  "contracts.studentTransit.desc": { en: "Prove active student status for discounted transit", uk: "Підтвердіть статус студента для пільгового проїзду" },
  "contracts.studentTransit.body_en": { en: "Party 1 (\"the Student\") has cryptographically proven that they hold an active student ID (valid through the current academic term). No name, university, faculty, or student number has been disclosed to the transit authority.\n\nThe transit operator knows only: (1) Party 1 is a currently enrolled student, and (2) the proof is bound to a valid student credential via its ID. This is sufficient to issue a discounted pass.", uk: "Party 1 (\"the Student\") has cryptographically proven that they hold an active student ID (valid through the current academic term). No name, university, faculty, or student number has been disclosed to the transit authority.\n\nThe transit operator knows only: (1) Party 1 is a currently enrolled student, and (2) the proof is bound to a valid student credential via its ID. This is sufficient to issue a discounted pass." },
  "contracts.studentTransit.body_uk": { en: "Особа 1 (\"Студент\") криптографічно довела, що має чинний студентський квиток (дійсний протягом поточного навчального семестру). Ім'я, університет, факультет та номер студентського квитка не розкриті транспортному оператору.\n\nОператор знає лише: (1) Особа 1 — студент, що навчається, та (2) доказ прив'язаний до чинного студентського посвідчення через його ID. Цього достатньо для видачі пільгового проїзного.", uk: "Особа 1 (\"Студент\") криптографічно довела, що має чинний студентський квиток (дійсний протягом поточного навчального семестру). Ім'я, університет, факультет та номер студентського квитка не розкриті транспортному оператору.\n\nОператор знає лише: (1) Особа 1 — студент, що навчається, та (2) доказ прив'язаний до чинного студентського посвідчення через його ID. Цього достатньо для видачі пільгового проїзного." },
  "contracts.driverEmployment.title": { en: "Driver Employment Contract", uk: "Договір найму водія" },
  "contracts.driverEmployment.desc": { en: "Verify valid license, category B, and 2+ years experience", uk: "Перевірити чинні права, категорію B та 2+ роки досвіду" },
  "contracts.driverEmployment.body_en": { en: "Party 1 (\"the Driver\") has cryptographically proven the following without revealing any personal information:\n\n• Their driver's license is currently valid (not expired)\n• Their license includes Category B authorization\n• They have at least 2 years of driving experience\n\nThe employer does not know Party 1's name, address, date of birth, or any license details beyond what is proven above. The proof is bound to a real government-issued license via its license number.", uk: "Party 1 (\"the Driver\") has cryptographically proven the following without revealing any personal information:\n\n• Their driver's license is currently valid (not expired)\n• Their license includes Category B authorization\n• They have at least 2 years of driving experience\n\nThe employer does not know Party 1's name, address, date of birth, or any license details beyond what is proven above. The proof is bound to a real government-issued license via its license number." },
  "contracts.driverEmployment.body_uk": { en: "Особа 1 (\"Водій\") криптографічно довела наступне без розкриття будь-якої персональної інформації:\n\n• Водійське посвідчення чинне (не прострочене)\n• Посвідчення включає категорію B\n• Щонайменше 2 роки водійського досвіду\n\nРоботодавець не знає імені Особи 1, адреси, дати народження чи будь-яких деталей посвідчення окрім доведеного вище. Доказ прив'язаний до реального державного посвідчення через його номер.", uk: "Особа 1 (\"Водій\") криптографічно довела наступне без розкриття будь-якої персональної інформації:\n\n• Водійське посвідчення чинне (не прострочене)\n• Посвідчення включає категорію B\n• Щонайменше 2 роки водійського досвіду\n\nРоботодавець не знає імені Особи 1, адреси, дати народження чи будь-яких деталей посвідчення окрім доведеного вище. Доказ прив'язаний до реального державного посвідчення через його номер." },
  "contracts.vehicleSale.title": { en: "Vehicle Sale Agreement", uk: "Договір купівлі-продажу ТЗ" },
  "contracts.vehicleSale.desc": { en: "Verify vehicle is insured and not collateral", uk: "Перевірити страхування ТЗ та відсутність застави" },
  "contracts.vehicleSale.body_en": { en: "Party 1 (\"the Seller\") and Party 2 (\"the Buyer\") enter this agreement under the following cryptographically proven conditions:\n\nSeller has proven:\n• They are at least 18 years of age\n• Their identity is bound to the vehicle registration (holder binding verified)\n\nThe vehicle (identified by VIN) has proven:\n• Insurance is currently active (not expired)\n• VIN is not in any revocation registry\n\nBuyer has proven:\n• They are at least 18 years of age\n\nNeither party's name, address, birthdate, or financial information has been disclosed. Each party is identified only by their document ID and the predicates they have proven. The holder binding proof cryptographically confirms that the Seller and the vehicle owner are the same person — without revealing who that person is.", uk: "Party 1 (\"the Seller\") and Party 2 (\"the Buyer\") enter this agreement under the following cryptographically proven conditions:\n\nSeller has proven:\n• They are at least 18 years of age\n• Their identity is bound to the vehicle registration (holder binding verified)\n\nThe vehicle (identified by VIN) has proven:\n• Insurance is currently active (not expired)\n• VIN is not in any revocation registry\n\nBuyer has proven:\n• They are at least 18 years of age\n\nNeither party's name, address, birthdate, or financial information has been disclosed. Each party is identified only by their document ID and the predicates they have proven. The holder binding proof cryptographically confirms that the Seller and the vehicle owner are the same person — without revealing who that person is." },
  "contracts.vehicleSale.body_uk": { en: "Особа 1 (\"Продавець\") та Особа 2 (\"Покупець\") укладають цей договір за наступних криптографічно доведених умов:\n\nПродавець довів:\n• Вік щонайменше 18 років\n• Його особа прив'язана до реєстрації ТЗ (зв'язок власника підтверджено)\n\nТранспортний засіб (ідентифікований за VIN) підтвердив:\n• Страхування чинне (не прострочене)\n• VIN не в реєстрі відкликань\n\nПокупець довів:\n• Вік щонайменше 18 років\n\nІм'я, адреса, дата народження та фінансова інформація жодної зі сторін не розкриті. Кожна сторона ідентифікована лише за ID документа та доведеними предикатами. Доказ прив'язки криптографічно підтверджує, що Продавець і власник ТЗ — одна й та сама особа, не розкриваючи, хто ця особа.", uk: "Особа 1 (\"Продавець\") та Особа 2 (\"Покупець\") укладають цей договір за наступних криптографічно доведених умов:\n\nПродавець довів:\n• Вік щонайменше 18 років\n• Його особа прив'язана до реєстрації ТЗ (зв'язок власника підтверджено)\n\nТранспортний засіб (ідентифікований за VIN) підтвердив:\n• Страхування чинне (не прострочене)\n• VIN не в реєстрі відкликань\n\nПокупець довів:\n• Вік щонайменше 18 років\n\nІм'я, адреса, дата народження та фінансова інформація жодної зі сторін не розкриті. Кожна сторона ідентифікована лише за ID документа та доведеними предикатами. Доказ прив'язки криптографічно підтверджує, що Продавець і власник ТЗ — одна й та сама особа, не розкриваючи, хто ця особа." },

  // ── Proposal page ─────────────────────────────────────────────────────
  "nav.proposal": { en: "TSP Proposal", uk: "Пропозиція TSP" },
  "proposal.title": {
    en: "Zero-Knowledge Selective Disclosure for eIDAS 2.0",
    uk: "Селективне розкриття з нульовим знанням для eIDAS 2.0",
  },
  "proposal.subtitle": {
    en: "A proposal for Qualified Trust Service Providers and national digital identity programmes",
    uk: "Пропозиція для кваліфікованих довірених постачальників послуг та національних програм цифрової ідентичності",
  },
  "proposal.problemTitle": { en: "The Problem", uk: "Проблема" },
  "proposal.problemDesc": {
    en: "Article 5a(16) of Regulation (EU) 2024/1183 mandates that European Digital Identity Wallets enable selective disclosure and unlinkability. The Architecture Reference Framework (ARF) recommends batch issuance as the primary mechanism, where the issuer pre-signs multiple copies of each credential so the holder can present each copy once without being tracked. This approach works but creates significant operational burden: N signatures per credential, N copies to store, N credentials to revoke. BBS+ signatures offer a more elegant alternative through rerandomization, but they are not part of the eIDAS standard and rely on pairing-based cryptography that is not quantum-resistant.",
    uk: "Стаття 5a(16) Регламенту (ЄС) 2024/1183 вимагає, щоб Європейські гаманці цифрової ідентичності забезпечували селективне розкриття та незв'язуваність. Architecture Reference Framework (ARF) рекомендує пакетну видачу як основний механізм, де емітент попередньо підписує кілька копій кожного посвідчення, щоб власник міг пред'явити кожну копію один раз без відстеження. Цей підхід працює, але створює значне операційне навантаження: N підписів на посвідчення, N копій для зберігання, N посвідчень для відкликання. Підписи BBS+ пропонують більш елегантну альтернативу через рерандомізацію, але вони не є частиною стандарту eIDAS і покладаються на криптографію на основі спарювань, яка не є квантово-стійкою.",
  },
  "proposal.solutionTitle": { en: "The Solution", uk: "Рішення" },
  "proposal.solutionDesc": {
    en: "zk-eidas uses zero-knowledge proofs to achieve true unlinkability from a single credential. The holder proves a statement about their data (e.g., \"I am over 18\") without revealing the underlying birth date or any other personal information. Each presentation is mathematically unlinkable — even the same holder proving the same fact to the same verifier produces a fresh, unique proof every time. No batch copies needed. One credential, unlimited unlinkable presentations.",
    uk: "zk-eidas використовує докази з нульовим знанням для досягнення справжньої незв'язуваності з одного посвідчення. Власник доводить твердження про свої дані (напр., \"мені понад 18 років\") без розкриття дати народження чи будь-якої іншої персональної інформації. Кожна презентація математично незв'язувана — навіть той самий власник, що доводить той самий факт тому самому верифікатору, генерує свіжий, унікальний доказ щоразу. Без пакетних копій. Одне посвідчення, необмежена кількість незв'язуваних презентацій.",
  },
  "proposal.provingTitle": { en: "Proving System", uk: "Система доведення" },
  "proposal.provingDesc": {
    en: "The zero-knowledge proofs are generated using Longfellow, a proving system developed by Google. It requires no trusted setup ceremony — there is no single point of failure and no coordinating authority needed to initialise the system. All cryptographic primitives are SOG-IS approved or NIST standardized, and the system provides post-quantum security: it remains secure even against future quantum computers.",
    uk: "Докази з нульовим знанням генеруються за допомогою Longfellow — системи доведення, розробленої Google. Вона не потребує церемонії довіреної ініціалізації — немає єдиної точки відмови та не потрібен координуючий орган для ініціалізації системи. Усі криптографічні примітиви затверджені SOG-IS або стандартизовані NIST, а система забезпечує пост-квантову безпеку: вона залишається захищеною навіть проти майбутніх квантових комп'ютерів.",
  },
  "proposal.tspTitle": { en: "Proposed QTSP Services", uk: "Запропоновані послуги QTSP" },
  "proposal.tspDesc": {
    en: "We propose two new qualified trust services under Article 45a of Regulation (EU) 2024/1183, deliverable by any existing Qualified Trust Service Provider:",
    uk: "Ми пропонуємо дві нові кваліфіковані довірені послуги згідно зі Статтею 45a Регламенту (ЄС) 2024/1183, які може надавати будь-який існуючий Кваліфікований Довірений Постачальник Послуг:",
  },
  "proposal.service1Title": { en: "Service 1: Proof Attestation", uk: "Послуга 1: Атестація доказу" },
  "proposal.service1Desc": {
    en: "The QTSP verifies a zero-knowledge proof and issues a Qualified Electronic Attestation of Attributes (QEAA) under Article 45d. The attestation is a W3C Verifiable Credential signed with the QTSP's qualified certificate. At ~1-2 KB, it fits in a single QR code — enabling offline verification without network connectivity.",
    uk: "QTSP перевіряє доказ з нульовим знанням і видає Кваліфіковану Електронну Атестацію Атрибутів (QEAA) згідно зі Статтею 45d. Атестація — це W3C Verifiable Credential, підписаний кваліфікованим сертифікатом QTSP. Розміром ~1-2 КБ, вона поміщається в один QR-код — забезпечуючи офлайн верифікацію без мережевого з'єднання.",
  },
  "proposal.service1Endpoint": {
    en: "Verify zero-knowledge proof → issue signed QEAA attestation",
    uk: "Перевірити доказ з нульовим знанням → видати підписану QEAA атестацію",
  },
  "proposal.service2Title": { en: "Service 2: Identity Escrow Custody", uk: "Послуга 2: Зберігання ескроу ідентичності" },
  "proposal.service2Desc": {
    en: "The QTSP holds the decryption key for identity escrow. When a citizen presents a zero-knowledge proof, their full identity fields are encrypted and attached as a sealed envelope. These fields can only be decrypted by the QTSP upon court order or arbitration ruling — ensuring accountability while preserving day-to-day privacy. The encryption uses ML-KEM-768, a NIST-standardized post-quantum algorithm.",
    uk: "QTSP зберігає ключ дешифрування для ескроу ідентичності. Коли громадянин пред'являє доказ з нульовим знанням, його повні дані ідентичності шифруються та додаються як запечатаний конверт. Ці поля можуть бути дешифровані QTSP лише за рішенням суду або арбітражу — забезпечуючи підзвітність при збереженні повсякденної приватності. Шифрування використовує ML-KEM-768, постквантовий алгоритм, стандартизований NIST.",
  },
  "proposal.service2Endpoint": {
    en: "Decrypt identity fields upon court authorization",
    uk: "Дешифрувати поля ідентичності за авторизацією суду",
  },
  "proposal.complianceTitle": { en: "Regulatory Alignment", uk: "Регуляторна відповідність" },
  "proposal.complianceItems": {
    en: "eIDAS 2.0 Article 5a(16): selective disclosure and unlinkability|eIDAS 2.0 Article 45a: Qualified Trust Service Provider obligations|eIDAS 2.0 Article 45d: Qualified Electronic Attestation of Attributes (QEAA)|ISO 18013-5: mdoc credential format (PID, mDL)|Architecture Reference Framework (ARF): compatible with existing EUDI Wallet architecture|SOG-IS / NIST: all cryptographic primitives approved or standardized|GDPR Article 25: privacy by design and by default",
    uk: "eIDAS 2.0 Стаття 5a(16): селективне розкриття та незв'язуваність|eIDAS 2.0 Стаття 45a: зобов'язання Кваліфікованих Довірених Постачальників Послуг|eIDAS 2.0 Стаття 45d: Кваліфікована Електронна Атестація Атрибутів (QEAA)|ISO 18013-5: формат посвідчень mdoc (PID, mDL)|Architecture Reference Framework (ARF): сумісність з існуючою архітектурою EUDI Wallet|SOG-IS / NIST: усі криптографічні примітиви затверджені або стандартизовані|GDPR Стаття 25: приватність за дизайном та за замовчуванням",
  },
  "proposal.integrationTitle": { en: "Integration Path", uk: "Шлях інтеграції" },
  "proposal.integrationDesc": {
    en: "Any existing Qualified Trust Service Provider can adopt these services with minimal infrastructure changes. The proving system runs as a single server-side component. The attestation service requires a qualified signing certificate (ECDSA P-256). The escrow service requires a post-quantum key pair stored in an HSM. No changes are required to the credential issuance infrastructure — the system works with standard mdoc credentials already issued by PID Providers. The approach is designed to fit within the Implementing Acts timeline for EUDI Wallet deployment (2026-2027).",
    uk: "Будь-який існуючий Кваліфікований Довірений Постачальник Послуг може впровадити ці послуги з мінімальними змінами інфраструктури. Система доведення працює як один серверний компонент. Послуга атестації потребує кваліфікований сертифікат підпису (ECDSA P-256). Послуга ескроу потребує пост-квантову ключову пару, що зберігається в HSM. Не потрібні зміни в інфраструктурі видачі посвідчень — система працює зі стандартними посвідченнями mdoc, вже виданими PID Providers. Підхід розроблений для відповідності графіку Implementing Acts щодо впровадження EUDI Wallet (2026-2027).",
  },
  "proposal.comparisonTitle": { en: "Approach Comparison", uk: "Порівняння підходів" },
  "proposal.comparisonSubtitle": {
    en: "How zk-eidas compares to the selective disclosure approaches currently considered for the EU Digital Identity Wallet.",
    uk: "Порівняння zk-eidas з підходами селективного розкриття, що зараз розглядаються для Європейського гаманця цифрової ідентичності.",
  },
  "proposal.col.batch": { en: "Batch Issuance (ARF)", uk: "Пакетна видача (ARF)" },
  "proposal.col.bbs": { en: "BBS+ Signatures", uk: "Підписи BBS+" },
  "proposal.col.zkeidas": { en: "zk-eidas", uk: "zk-eidas" },
  "proposal.row.eidasStatus": { en: "eIDAS 2.0 status", uk: "Статус eIDAS 2.0" },
  "proposal.row.selectiveDisclosure": { en: "Selective disclosure", uk: "Селективне розкриття" },
  "proposal.row.predicates": { en: "Predicate proofs (e.g., age >= 18)", uk: "Предикатні докази (напр., вік >= 18)" },
  "proposal.row.unlinkability": { en: "Unlinkability (Art. 5a(16))", uk: "Незв'язуваність (Ст. 5a(16))" },
  "proposal.row.holderBinding": { en: "Holder binding", uk: "Прив'язка до власника" },
  "proposal.row.identityEscrow": { en: "Identity escrow (accountability)", uk: "Ескроу ідентичності (підзвітність)" },
  "proposal.row.trustedSetup": { en: "Trusted setup required", uk: "Потрібна довірена ініціалізація" },
  "proposal.row.quantumSafe": { en: "Post-quantum security", uk: "Пост-квантова безпека" },
  "proposal.row.issuerLoad": { en: "Issuer load per credential", uk: "Навантаження на емітента" },
  "proposal.row.holderStorage": { en: "Holder storage", uk: "Зберігання у власника" },
  "proposal.row.revocation": { en: "Revocation complexity", uk: "Складність відкликання" },
  "proposal.row.proofSize": { en: "Presentation size", uk: "Розмір презентації" },
  "proposal.row.crossBorder": { en: "Cross-border interoperability", uk: "Транскордонна сумісність" },
  "proposal.row.auditTrail": { en: "Third-party audit / verification", uk: "Аудит / верифікація третьою стороною" },
  "proposal.cell.batch.eidas": { en: "ARF recommended", uk: "Рекомендовано ARF" },
  "proposal.cell.batch.sd": { en: "Yes (per-copy)", uk: "Так (по-копійно)" },
  "proposal.cell.batch.predicates": { en: "Issuer pre-computes (e.g., age_over_18 field)", uk: "Емітент попередньо обчислює (напр., поле age_over_18)" },
  "proposal.cell.batch.unlinkability": { en: "Limited by copy count", uk: "Обмежена кількістю копій" },
  "proposal.cell.batch.binding": { en: "Per-copy key", uk: "Ключ на кожну копію" },
  "proposal.cell.batch.escrow": { en: "Not supported", uk: "Не підтримується" },
  "proposal.cell.batch.setup": { en: "No", uk: "Ні" },
  "proposal.cell.batch.quantum": { en: "Depends on signature scheme", uk: "Залежить від схеми підпису" },
  "proposal.cell.batch.issuerLoad": { en: "N signatures per credential", uk: "N підписів на посвідчення" },
  "proposal.cell.batch.storage": { en: "N copies per credential", uk: "N копій на посвідчення" },
  "proposal.cell.batch.revocation": { en: "Revoke N credentials", uk: "Відкликати N посвідчень" },
  "proposal.cell.batch.size": { en: "~100-200 bytes", uk: "~100-200 байт" },
  "proposal.cell.batch.crossBorder": { en: "Yes (standard mdoc)", uk: "Так (стандартний mdoc)" },
  "proposal.cell.batch.auditTrail": { en: "Signature check only", uk: "Лише перевірка підпису" },
  "proposal.cell.bbs.eidas": { en: "Not in Regulation", uk: "Не в Регламенті" },
  "proposal.cell.bbs.sd": { en: "Yes", uk: "Так" },
  "proposal.cell.bbs.predicates": { en: "Issuer pre-computes (e.g., age_over_18 field)", uk: "Емітент попередньо обчислює (напр., поле age_over_18)" },
  "proposal.cell.bbs.unlinkability": { en: "Built-in (rerandomization)", uk: "Вбудована (рерандомізація)" },
  "proposal.cell.bbs.binding": { en: "Linkable across presentations", uk: "Зв'язуваний між презентаціями" },
  "proposal.cell.bbs.escrow": { en: "Not supported", uk: "Не підтримується" },
  "proposal.cell.bbs.setup": { en: "No", uk: "Ні" },
  "proposal.cell.bbs.quantum": { en: "No (pairing-based cryptography)", uk: "Ні (криптографія на базі спарювань)" },
  "proposal.cell.bbs.issuerLoad": { en: "1 signature", uk: "1 підпис" },
  "proposal.cell.bbs.storage": { en: "1 credential", uk: "1 посвідчення" },
  "proposal.cell.bbs.revocation": { en: "Revoke 1", uk: "Відкликати 1" },
  "proposal.cell.bbs.size": { en: "~100 bytes", uk: "~100 байт" },
  "proposal.cell.bbs.crossBorder": { en: "Requires new standard adoption", uk: "Потребує прийняття нового стандарту" },
  "proposal.cell.bbs.auditTrail": { en: "Computationally expensive", uk: "Обчислювально дорого" },
  "proposal.cell.zk.eidas": { en: "QEAA-compatible (Art. 45d)", uk: "Сумісний з QEAA (Ст. 45d)" },
  "proposal.cell.zk.sd": { en: "Yes", uk: "Так" },
  "proposal.cell.zk.predicates": { en: "Holder-side — any threshold, at presentation time", uk: "На стороні власника — будь-який поріг, у момент презентації" },
  "proposal.cell.zk.unlinkability": { en: "Mathematical (unlimited presentations)", uk: "Математична (необмежена кількість презентацій)" },
  "proposal.cell.zk.binding": { en: "Unlinkable device binding", uk: "Незв'язувана прив'язка до пристрою" },
  "proposal.cell.zk.escrow": { en: "Encrypted identity, released by court order", uk: "Зашифрована ідентичність, розкривається за рішенням суду" },
  "proposal.cell.zk.setup": { en: "No (transparent system)", uk: "Ні (прозора система)" },
  "proposal.cell.zk.quantum": { en: "Yes (NIST-standardized primitives)", uk: "Так (примітиви, стандартизовані NIST)" },
  "proposal.cell.zk.issuerLoad": { en: "1 signature", uk: "1 підпис" },
  "proposal.cell.zk.storage": { en: "1 credential", uk: "1 посвідчення" },
  "proposal.cell.zk.revocation": { en: "Revoke 1", uk: "Відкликати 1" },
  "proposal.cell.zk.size": { en: "~360 KB proof + ~1-2 KB QEAA", uk: "~360 КБ доказ + ~1-2 КБ QEAA" },
  "proposal.cell.zk.crossBorder": { en: "Yes (standard mdoc + QEAA)", uk: "Так (стандартний mdoc + QEAA)" },
  "proposal.cell.zk.auditTrail": { en: "QEAA attestation, verifiable by any party", uk: "QEAA атестація, верифікована будь-якою стороною" },
  "proposal.tryDemo": { en: "Try the Live Demo", uk: "Спробувати демо" },
};

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

interface LocaleContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
}

const LocaleContext = createContext<LocaleContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function LocaleProvider({ children }: { children: ReactNode }) {
  // Always start with DEFAULT_LOCALE so SSR and first client render match (avoids hydration mismatch).
  // Then sync from localStorage in useEffect.
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if ((stored === "en" || stored === "uk") && stored !== DEFAULT_LOCALE) {
        setLocaleState(stored);
      }
    } catch {
      // localStorage may be unavailable
    }
  }, []);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // ignore
    }
  }, []);

  return (
    <LocaleContext.Provider value={{ locale, setLocale }}>
      {children}
    </LocaleContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export function useLocale(): { locale: Locale; setLocale: (l: Locale) => void } {
  const ctx = useContext(LocaleContext);
  if (!ctx) {
    throw new Error("useLocale must be used within a <LocaleProvider>");
  }
  return ctx;
}

export function useT(): (key: string) => string {
  const { locale } = useLocale();

  return useCallback(
    (key: string): string => {
      const entry = translations[key];
      if (!entry) return key;
      return entry[locale] ?? key;
    },
    [locale],
  );
}

/** Translate a key for a specific locale (useful for bilingual documents) */
export function tLang(key: string, lang: 'en' | 'uk'): string {
  const entry = translations[key];
  if (!entry) return key;
  return entry[lang] ?? key;
}
