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
    en: "An eIDAS 2.0 compatible unlinkability layer",
    uk: "Шар незв'язуваності, сумісний з eIDAS 2.0",
  },
  "hero.tagline": {
    en: "EU mandates unlinkability. The approved credential formats can't provide it. We fix that.",
    uk: "ЄС вимагає незв'язуваність. Затверджені формати посвідчень не можуть її забезпечити. Ми це виправляємо.",
  },
  "hero.tryDemo": { en: "Try the Demo", uk: "Спробувати демо" },
  "hero.viewGithub": { en: "View on GitHub", uk: "Переглянути на GitHub" },

  // ── Problem ──────────────────────────────────────────────────────────
  "problem.title": {
    en: "The Unlinkability Gap",
    uk: "Прогалина незв'язуваності",
  },
  "problem.subtitle": {
    en: "eIDAS 2.0 Article 5a(16) requires unlinkability. SD-JWT VC with ES256 structurally can't deliver it — every presentation is linkable by the issuer's signature. BBS+ is not on the SOG-IS approved algorithm list. Batch issuance doesn't support predicates.",
    uk: "Стаття 5a(16) eIDAS 2.0 вимагає незв'язуваність. SD-JWT VC з ES256 структурно не може її забезпечити — кожна презентація зв'язувана через підпис видавця. BBS+ не включено до списку схвалених алгоритмів SOG-IS. Пакетна видача не підтримує предикати.",
  },
  "problem.criterion": { en: "Criterion", uk: "Критерій" },
  "problem.sdjwt": { en: "SD-JWT VC", uk: "SD-JWT VC" },
  "problem.bbs": { en: "BBS+", uk: "BBS+" },
  "problem.batch": { en: "Batch Issuance", uk: "Пакетна видача" },
  "problem.zk": { en: "ZK Proofs", uk: "ZK-докази" },
  "problem.row1": { en: "eIDAS 2.0 format compliant", uk: "Сумісність з форматом eIDAS 2.0" },
  "problem.row2": { en: "SOG-IS approved algorithms", uk: "Алгоритми схвалені SOG-IS" },
  "problem.row3": { en: "Unlinkable presentations", uk: "Незв'язувані презентації" },
  "problem.row4": { en: "Selective disclosure", uk: "Вибіркове розкриття" },
  "problem.row5": { en: "Predicate proofs (e.g. age \u2265 18)", uk: "Предикатні докази (напр. вік \u2265 18)" },
  "problem.row6": { en: "No infrastructure changes", uk: "Без змін інфраструктури" },

  // ── Solution ─────────────────────────────────────────────────────────
  "solution.title": {
    en: "ZK proofs over existing credentials",
    uk: "ZK-докази поверх існуючих посвідчень",
  },
  "solution.subtitle": {
    en: "No format changes. No new algorithms. No infrastructure.",
    uk: "Без змін формату. Без нових алгоритмів. Без інфраструктури.",
  },
  "solution.step1Title": {
    en: "Issuer signs ES256",
    uk: "Видавець підписує ES256",
  },
  "solution.step1Desc": {
    en: "Standard SD-JWT VC or mdoc issuance. No changes to the issuer's infrastructure.",
    uk: "Стандартна видача SD-JWT VC або mdoc. Без змін інфраструктури видавця.",
  },
  "solution.step1Label": {
    en: "as usual",
    uk: "як зазвичай",
  },
  "solution.step2Title": {
    en: "User proves in ZK circuit",
    uk: "Користувач доводить у ZK-схемі",
  },
  "solution.step2Desc": {
    en: "ECDSA signature verified inside the circuit. The claim value never leaves the device.",
    uk: "Підпис ECDSA перевіряється всередині схеми. Значення поля ніколи не залишає пристрій.",
  },
  "solution.step3Title": {
    en: "Verifier checks proof",
    uk: "Верифікатор перевіряє доказ",
  },
  "solution.step3Desc": {
    en: "Millisecond verification. Works offline. Zero personal data exposed.",
    uk: "Верифікація за мілісекунди. Працює офлайн. Нуль персональних даних розкрито.",
  },

  // ── Pre-commitment ───────────────────────────────────────────────────
  "precommit.title": {
    en: "< 1 second on any smartphone",
    uk: "< 1 секунда на будь-якому смартфоні",
  },
  "precommit.subtitle": {
    en: "Heavy ECDSA once at issuance — lightweight Poseidon proofs forever",
    uk: "Важкий ECDSA один раз при видачі — легкі Poseidon-докази назавжди",
  },
  "precommit.desc": {
    en: "The ECDSA P-256 signature verification is the most expensive part of the proof — millions of constraints. Pre-computing it at credential issuance time means the user's device only needs to run lightweight Poseidon-based predicate circuits at presentation time.",
    uk: "Перевірка підпису ECDSA P-256 — найважча частина доказу: мільйони обмежень. Попередній розрахунок при видачі посвідчення означає, що пристрій користувача запускає лише легкі Poseidon-схеми предикатів при пред'явленні.",
  },
  "precommit.device": { en: "Device", uk: "Пристрій" },
  "precommit.time": { en: "Predicate proof time", uk: "Час доказу предиката" },
  "precommit.badge": { en: "planned", uk: "в розробці" },

  // ── Ukraine ──────────────────────────────────────────────────────────
  "ukraine.title": {
    en: "Built for scale. Proven by Diia.",
    uk: "Побудовано для масштабу. Доведено Дією.",
  },
  "ukraine.stat1": { en: "active users", uk: "активних користувачів" },
  "ukraine.stat2": { en: "countries exported to", uk: "країн експорту" },
  "ukraine.stat3": { en: "wallet pilot participant", uk: "учасник пілоту гаманця" },
  "ukraine.desc": {
    en: "Ukraine is the only non-EU country in the POTENTIAL EUDI Wallet pilot. Diia — the most widely deployed digital identity app in Europe — is open source and runs on the same credential formats zk-eidas supports. We're building the unlinkability layer.",
    uk: "Україна — єдина країна поза ЄС у пілоті POTENTIAL EUDI Wallet. Дія — найпоширеніший застосунок цифрової ідентичності в Європі — має відкритий код і працює на тих самих форматах посвідчень, що підтримує zk-eidas. Ми будуємо шар незв'язуваності.",
  },

  // ── Learn More page ─────────────────────────────────────────────────────
  "learn.back": { en: "Back", uk: "Назад" },
  "learn.title": { en: "Why Zero-Knowledge for eIDAS 2.0", uk: "Чому Zero-Knowledge для eIDAS 2.0" },
  "learn.subtitle": {
    en: "eIDAS 2.0 mandates unlinkability. The approved credential formats cannot provide it. Zero-knowledge proofs are the only compliant solution.",
    uk: "eIDAS 2.0 вимагає незв'язуваності. Затверджені формати посвідчень не можуть її забезпечити. Докази з нульовим розголошенням — єдине відповідне рішення.",
  },
  "learn.cta": { en: "Try the Playground", uk: "Спробувати пісочницю" },

  // TOC
  "learn.tocProblem": { en: "The Problem", uk: "Проблема" },
  "learn.tocWhyZk": { en: "Why ZK", uk: "Чому ZK" },
  "learn.tocComparison": { en: "Comparison", uk: "Порівняння" },
  "learn.tocTrustGap": { en: "Trust Gap", uk: "Прогалина довіри" },
  "learn.tocHowItWorks": { en: "How It Works", uk: "Як це працює" },
  "learn.tocCapabilities": { en: "Capabilities", uk: "Можливості" },
  "learn.tocStandards": { en: "Standards", uk: "Стандарти" },
  "learn.tocPrivacy": { en: "GDPR", uk: "GDPR" },

  // 1. The eIDAS 2.0 Unlinkability Problem
  "learn.problemTitle": { en: "The eIDAS 2.0 Unlinkability Problem", uk: "Проблема незв'язуваності eIDAS 2.0" },
  "learn.problemSubtitle": {
    en: "Article 5a(16) of the eIDAS 2.0 regulation requires that relying parties cannot link presentations of attributes from the same or different attestations. This is not optional — it is law.",
    uk: "Стаття 5a(16) регламенту eIDAS 2.0 вимагає, щоб сторони, які покладаються, не могли пов'язувати пред'явлення атрибутів з одних і тих самих або різних атестацій. Це не опція — це закон.",
  },
  "learn.problemSubtitleAfterLink": {
    en: "of the eIDAS 2.0 regulation (EU 2024/1183) requires that relying parties cannot link presentations of attributes from the same or different attestations. This is not optional — it is law.",
    uk: "регламенту eIDAS 2.0 (EU 2024/1183) вимагає, щоб сторони, які покладаються, не могли пов'язувати пред'явлення атрибутів з одних і тих самих або різних атестацій. Це не опція — це закон.",
  },
  "learn.problemSdjwtLabel": { en: "SD-JWT VC Presentation", uk: "Пред'явлення SD-JWT VC" },
  "learn.problemSdjwtSees": { en: "// every verifier sees:", uk: "// кожен верифікатор бачить:" },
  "learn.problemSdjwtSig": { en: "same every time", uk: "однаковий кожного разу" },
  "learn.problemSdjwtCnf": { en: "same every time", uk: "однаковий кожного разу" },
  "learn.problemSdjwtClaim": { en: "disclosed claim", uk: "розкрите поле" },
  "learn.problemSdjwtHidden": { en: "hidden claim", uk: "приховане поле" },
  "learn.problemZkLabel": { en: "zk-eidas Presentation", uk: "Пред'явлення zk-eidas" },
  "learn.problemZkSees": { en: "// verifier sees:", uk: "// верифікатор бачить:" },
  "learn.problemZkResult": { en: "boolean result only", uk: "лише булевий результат" },
  "learn.problemZkSigValid": { en: "verified inside circuit", uk: "перевірено в схемі" },
  "learn.problemZkNullifier": { en: "unique per service", uk: "унікальний для сервісу" },
  "learn.problemZkHidden": { en: "never transmitted", uk: "ніколи не передається" },
  "learn.problemZkSigHidden": { en: "never revealed", uk: "ніколи не розкривається" },
  "learn.problemSdjwtTitle": { en: "SD-JWT VC Linkability", uk: "Зв'язуваність SD-JWT VC" },
  "learn.problemSdjwtDesc": {
    en: "The issuer's ECDSA signature and the cnf (confirmation) key are identical in every presentation. Any two verifiers comparing notes can trivially correlate them to the same holder.",
    uk: "ECDSA підпис видавця та cnf (підтверджувальний) ключ ідентичні у кожному пред'явленні. Будь-які два верифікатори можуть тривіально скорелювати їх з одним власником.",
  },
  "learn.problemBbsTitle": { en: "BBS+ Not SOG-IS Compliant", uk: "BBS+ не відповідає SOG-IS" },
  "learn.problemBbsDesc": {
    en: "BBS+ signatures solve unlinkability mathematically. However, BBS+ relies on bilinear pairings — not on the SOG-IS approved algorithms list. The European Commission rejected BBS+ for EUDI Wallets on these grounds.",
    uk: "Підписи BBS+ вирішують незв'язуваність математично. Проте BBS+ використовує білінійні спарювання — відсутні у переліку схвалених алгоритмів SOG-IS. Європейська Комісія відхилила BBS+ для EUDI Wallets саме з цих підстав.",
  },
  "learn.problemBatchTitle": { en: "Batch Issuance Impractical", uk: "Пакетна видача непрактична" },
  "learn.problemBatchDesc": {
    en: "Issuing N credential copies with different keys: N-fold storage, per-copy revocation, no selective disclosure, N must be estimated in advance.",
    uk: "Видача N копій посвідчень з різними ключами: N-кратне зберігання, відкликання по-копійно, без селективного розкриття, N треба оцінити заздалегідь.",
  },
  "learn.problemClosing": {
    en: "The regulation demands unlinkability. The approved formats cannot provide it. This is a structural gap.",
    uk: "Регламент вимагає незв'язуваності. Затверджені формати не можуть її забезпечити. Це структурна прогалина.",
  },

  // 2. Why Only ZK Works
  "learn.whyZkTitle": { en: "Why Only Zero-Knowledge Works", uk: "Чому тільки Zero-Knowledge працює" },
  "learn.whyZkDesc": {
    en: "Instead of presenting a credential to a verifier, the holder proves its validity inside a cryptographic circuit. The issuer's signature is verified but never revealed. Each presentation is mathematically unique — unlinkability is a property of the proof system, not an organizational policy.",
    uk: "Замість пред'явлення посвідчення верифікатору, власник доводить його дійсність всередині криптографічної схеми. Підпис видавця перевіряється, але ніколи не розкривається. Кожне пред'явлення математично унікальне — незв'язуваність є властивістю системи доведення, а не організаційною політикою.",
  },
  "learn.whyZkCompleteness": { en: "Completeness", uk: "Повнота" },
  "learn.whyZkCompletenessDesc": { en: "Valid credentials always produce valid proofs. A legitimate holder is never rejected.", uk: "Дійсні посвідчення завжди створюють дійсні докази. Легітимний власник ніколи не відхиляється." },
  "learn.whyZkSoundness": { en: "Soundness", uk: "Надійність" },
  "learn.whyZkSoundnessDesc": { en: "Invalid credentials cannot produce valid proofs. Fabrication is computationally impossible.", uk: "Недійсні посвідчення не можуть створити дійсні докази. Фабрикація обчислювально неможлива." },
  "learn.whyZkZeroKnowledge": { en: "Zero Knowledge", uk: "Нуль знань" },
  "learn.whyZkZeroKnowledgeDesc": { en: "The verifier learns only the boolean predicate result. No claim values, no signature, no metadata.", uk: "Верифікатор дізнається лише булевий результат предиката. Жодних значень полів, підписів, метаданих." },
  "learn.whyZkClosing": {
    en: "ZK is the only primitive that provides unlinkability, selective disclosure, and SOG-IS-approved cryptography simultaneously.",
    uk: "ZK — єдиний примітив, що забезпечує незв'язуваність, селективне розкриття та схвалену SOG-IS криптографію одночасно.",
  },

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
  "learn.compFormatZk": { en: "Native SD-JWT / mdoc", uk: "Нативний SD-JWT / mdoc" },
  "learn.compSize": { en: "Proof Size", uk: "Розмір доказу" },
  "learn.compSizeFull": { en: "Full disclosed claims", uk: "Повні розкриті поля" },
  "learn.compSizeBbs": { en: "~200 bytes", uk: "~200 байт" },
  "learn.compSizeZk": { en: "~800 bytes", uk: "~800 байт" },
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

  // 4. The Trust Gap
  "learn.trustGapTitle": { en: "The Trust Gap", uk: "Прогалина довіри" },
  "learn.trustGapSubtitle": {
    en: "Why zk-eidas is different from other ZK credential systems: ECDSA signature verification happens inside the circuit, not outside.",
    uk: "Чому zk-eidas відрізняється від інших ZK систем для посвідчень: перевірка підпису ECDSA відбувається всередині схеми, а не ззовні.",
  },
  "learn.trustGapTypical": { en: "Most ZK Implementations", uk: "Більшість ZK реалізацій" },
  "learn.trustGapTyp1": { en: "The issuer's signature is verified externally — outside the ZK circuit.", uk: "Підпис видавця перевіряється зовні — поза ZK схемою." },
  "learn.trustGapTyp2": { en: "The predicate is proved inside the circuit using self-supplied data.", uk: "Предикат доводиться всередині схеми з використанням самостійно наданих даних." },
  "learn.trustGapTyp3": { en: "Nothing cryptographically binds the verified signature to the data inside the circuit.", uk: "Ніщо криптографічно не зв'язує перевірений підпис з даними всередині схеми." },
  "learn.trustGapTyp4": { en: "A holder could fabricate claim values fed into the predicate circuit.", uk: "Власник може сфабрикувати значення полів, подані в схему предиката." },
  "learn.trustGapTyp5": { en: "\"The proof says age ≥ 18, but from which credential?\"", uk: "\"Доказ каже вік ≥ 18, але з якого посвідчення?\"" },
  "learn.trustGapZkTitle": { en: "zk-eidas: Full-Chain Verification", uk: "zk-eidas: повноланцюгова верифікація" },
  "learn.trustGapZk1": { en: "ECDSA P-256 signature verification runs inside the same Circom circuit as the predicate.", uk: "Перевірка підпису ECDSA P-256 відбувається всередині тієї ж Circom схеми, що й предикат." },
  "learn.trustGapZk2": { en: "The circuit re-derives the SHA-256 disclosure hash and checks it against the signed payload.", uk: "Схема повторно обчислює SHA-256 хеш розкриття та перевіряє його проти підписаного payload." },
  "learn.trustGapZk3": { en: "Fabrication is impossible — the proof covers the entire chain:", uk: "Фабрикація неможлива — доказ покриває весь ланцюг:" },
  "learn.trustGapChain": { en: "Issuer Signature → Claim Binding → Predicate Logic", uk: "Підпис видавця → Прив'язка поля → Логіка предиката" },
  "learn.trustGapClosing": {
    en: "Other ZK systems prove predicates. zk-eidas proves the predicate AND that the data is authentic.",
    uk: "Інші ZK системи доводять предикати. zk-eidas доводить предикат І те, що дані автентичні.",
  },

  // 5. How It Works
  "learn.howTitle": { en: "How It Works", uk: "Як це працює" },
  "learn.howSubtitle": {
    en: "From credential to proof in five steps.",
    uk: "Від посвідчення до доказу за п'ять кроків.",
  },
  "learn.howCredential": { en: "Credential", uk: "Посвідчення" },
  "learn.howParser": { en: "Parser", uk: "Парсер" },
  "learn.howParserSub": { en: "Claims + Key", uk: "Поля + Ключ" },
  "learn.howWitness": { en: "Witness", uk: "Свідок" },
  "learn.howWitnessSub": { en: "Circuit Inputs", uk: "Входи схеми" },
  "learn.howCircuit": { en: "Circuit", uk: "Схема" },
  "learn.howCircuitSub": { en: "ECDSA + Predicate", uk: "ECDSA + Предикат" },
  "learn.howProof": { en: "Proof", uk: "Доказ" },
  "learn.howProofSub": { en: "Groth16", uk: "Groth16" },
  "learn.howVerifier": { en: "Verifier", uk: "Верифікатор" },
  "learn.howVerifierSub": { en: "Pass / Fail", uk: "Так / Ні" },
  "learn.howStep1Title": { en: "Parse", uk: "Розбір" },
  "learn.howStep1Desc": { en: "Extract individual claims and the issuer's public key from the SD-JWT VC or mdoc credential.", uk: "Витягнути окремі поля та публічний ключ видавця з SD-JWT VC або mdoc посвідчення." },
  "learn.howStep2Title": { en: "Witness", uk: "Свідок" },
  "learn.howStep2Desc": { en: "Convert claim values to circuit inputs: dates become integers, strings become hashes.", uk: "Конвертувати значення полів у входи схеми: дати стають цілими числами, рядки — хешами." },
  "learn.howStep3Title": { en: "Circuit", uk: "Схема" },
  "learn.howStep3Desc": { en: "Verify the ECDSA signature and evaluate the predicate in a single Circom execution.", uk: "Перевірити підпис ECDSA та обчислити предикат за одне виконання Circom." },
  "learn.howStep4Title": { en: "Prove", uk: "Доведення" },
  "learn.howStep4Desc": { en: "Generate a Groth16 proof (~2 seconds on server, ~4 minutes in browser).", uk: "Згенерувати Groth16 доказ (~2 секунди на сервері, ~4 хвилини в браузері)." },
  "learn.howStep5Title": { en: "Verify", uk: "Верифікація" },
  "learn.howStep5Desc": { en: "Check the proof against the verification key. <10ms on server, <100ms in browser. Works offline.", uk: "Перевірити доказ проти ключа верифікації. <10мс на сервері, <100мс у браузері. Працює офлайн." },
  "learn.howMetricSize": { en: "proof size", uk: "розмір доказу" },
  "learn.howMetricVerify": { en: "verification", uk: "верифікація" },
  "learn.howMetricOffline": { en: "Offline", uk: "Офлайн" },
  "learn.howMetricOfflineDesc": { en: "no network required", uk: "без мережі" },
  "learn.howMetricDevice": { en: "Any device", uk: "Будь-який пристрій" },
  "learn.howMetricDeviceDesc": { en: "server or browser", uk: "сервер або браузер" },

  // 6. Capabilities
  "learn.capabilitiesTitle": { en: "Capabilities", uk: "Можливості" },
  "learn.capabilitiesSubtitle": {
    en: "Seven predicate types and four advanced features — all with in-circuit ECDSA signature verification.",
    uk: "Сім типів предикатів та чотири розширені можливості — всі з перевіркою підпису ECDSA всередині схеми.",
  },
  "learn.capType": { en: "Type", uk: "Тип" },
  "learn.capDescription": { en: "Description", uk: "Опис" },
  "learn.capExample": { en: "Example", uk: "Приклад" },
  "learn.capGteDesc": { en: "Greater than or equal", uk: "Більше або дорівнює" },
  "learn.capLteDesc": { en: "Less than or equal", uk: "Менше або дорівнює" },
  "learn.capEqDesc": { en: "Equality (hash-based)", uk: "Рівність (на основі хешу)" },
  "learn.capNeqDesc": { en: "Not equal", uk: "Не дорівнює" },
  "learn.capRangeDesc": { en: "Value within bounds", uk: "Значення в межах" },
  "learn.capSetDesc": { en: "One of up to 16 values", uk: "Одне з до 16 значень" },
  "learn.capNullDesc": { en: "Scoped replay prevention", uk: "Скопована протидія повтору" },
  "learn.capCompoundTitle": { en: "Compound Predicates", uk: "Складені предикати" },
  "learn.capCompoundDesc": {
    en: "Combine multiple predicates with AND/OR logic. Each sub-proof independently verifies its own ECDSA signature.",
    uk: "Поєднуйте кілька предикатів за допомогою логіки AND/OR. Кожен під-доказ незалежно перевіряє свій ECDSA підпис.",
  },
  "learn.capNullifierTitle": { en: "Scoped Nullifiers", uk: "Скоповані нуліфікатори" },
  "learn.capNullifierDesc": {
    en: "Deterministic per-service tokens derived from the holder's secret and the verifier's scope. Same credential, different service = different nullifier. Cross-service linking is impossible.",
    uk: "Детерміновані токени для кожного сервісу, отримані з секрету власника та скопу верифікатора. Одне посвідчення, різні сервіси = різні нуліфікатори. Міжсервісне зв'язування неможливе.",
  },
  "learn.capRevocationTitle": { en: "Credential Revocation", uk: "Відкликання посвідчень" },
  "learn.capRevocationDesc": {
    en: "Sparse Merkle Tree non-membership proof, verified inside the circuit. The issuer publishes the tree root; the holder proves their credential is not in the revocation set.",
    uk: "Доказ невключення через розріджене дерево Меркла, перевірений всередині схеми. Видавець публікує корінь дерева; власник доводить, що його посвідчення не у множині відкликаних.",
  },
  "learn.capBindingTitle": { en: "Holder Binding", uk: "Прив'язка власника" },
  "learn.capBindingDesc": {
    en: "Prove that two credentials (e.g., national ID and driver's license) belong to the same person, without revealing the shared identifier.",
    uk: "Доведіть, що два посвідчення (напр., національний ID та водійські права) належать одній особі, не розкриваючи спільний ідентифікатор.",
  },
  "learn.capNote": {
    en: "Every predicate circuit includes full ECDSA P-256 signature verification. All proofs are cryptographically bound to authentic credentials.",
    uk: "Кожна схема предиката включає повну перевірку підпису ECDSA P-256. Всі докази криптографічно прив'язані до автентичних посвідчень.",
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
    en: "Selective Disclosure for JWTs (RFC 9901) with the Verifiable Credentials profile (draft-ietf-oauth-sd-jwt-vc). The primary credential format for EUDI Wallets. Each claim is individually disclosable via salted SHA-256 hashes.",
    uk: "Selective Disclosure для JWT (RFC 9901) з профілем Verifiable Credentials (draft-ietf-oauth-sd-jwt-vc). Основний формат посвідчень для EUDI Wallets. Кожне поле може розкриватися окремо через SHA-256 хеші з сіллю.",
  },
  "learn.stdMdoc": {
    en: "Mobile document format with COSE_Sign1 signatures. Used for mobile driver's licenses. zk-eidas verifies COSE_Sign1 signatures inside the same ZK circuits.",
    uk: "Формат мобільних документів з підписами COSE_Sign1. Використовується для мобільних водійських посвідчень. zk-eidas перевіряє підписи COSE_Sign1 всередині тих самих ZK схем.",
  },
  "learn.stdEcdsa": {
    en: "The signature algorithm specified by both SD-JWT VC (ES256) and mdoc (COSE_Sign1). P-256 curve, verified inside the Circom circuit for every proof.",
    uk: "Алгоритм підпису, визначений як для SD-JWT VC (ES256), так і для mdoc (COSE_Sign1). Крива P-256, перевіряється всередині Circom схеми для кожного доказу.",
  },
  "learn.stdOpenid": {
    en: "The transport protocol for requesting and receiving ZK proofs from EUDI Wallets.",
    uk: "Транспортний протокол для запиту та отримання ZK доказів від EUDI Wallets.",
  },
  "learn.stdArf": {
    en: "Compatible with Architecture Reference Framework v1.4 PID and mDL credential profiles. Conformance tests validate against the exact ARF credential schemas.",
    uk: "Сумісний з Architecture Reference Framework v1.4 профілями PID та mDL. Тести відповідності валідують саме ARF схеми посвідчень.",
  },
  "learn.stdSogis": {
    en: "All cryptographic primitives (ECDSA P-256, SHA-256) are on the SOG-IS approved list. Poseidon hash is used only in the presentation layer for commitment chaining — outside the scope of SOG-IS requirements for credential issuance.",
    uk: "Всі криптографічні примітиви (ECDSA P-256, SHA-256) у переліку схвалених SOG-IS. Хеш Poseidon використовується лише у шарі пред'явлення для ланцюжка комітментів — поза сферою вимог SOG-IS до видачі посвідчень.",
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

  // ── Live Proof ─────────────────────────────────────────────────────────
  "liveProof.title": {
    en: "See eIDAS 2.0 unlinkability in action",
    uk: "Незв'язуваність eIDAS 2.0 в дії",
  },
  "liveProof.subtitle": {
    en: "Generate a real ZK proof, then verify it entirely in your browser. Each proof is randomized — no two presentations are linkable.",
    uk: "Згенеруйте справжній ZK-доказ, потім перевірте його у вашому браузері. Кожен доказ рандомізований — жодні дві презентації не зв'язувані.",
  },
  "liveProof.scenario": {
    en: "Prove: age \u2265 18 (from a national ID credential)",
    uk: "Довести: вік \u2265 18 (з національного ID)",
  },
  "liveProof.generate": {
    en: "Generate ZK Proof",
    uk: "Згенерувати ZK-доказ",
  },
  "liveProof.generating": {
    en: "Generating proof...",
    uk: "Генерація доказу...",
  },
  "liveProof.verify": {
    en: "Verify in Your Browser",
    uk: "Перевірити у вашому браузері",
  },
  "liveProof.verifying": {
    en: "Verifying...",
    uk: "Перевірка...",
  },
  "liveProof.proofGenerated": {
    en: "Proof generated",
    uk: "Доказ згенеровано",
  },
  "liveProof.verified": {
    en: "Verified",
    uk: "Підтверджено",
  },
  "liveProof.proveTime": {
    en: "Prove time",
    uk: "Час генерації",
  },
  "liveProof.verifyTime": {
    en: "Verify time",
    uk: "Час перевірки",
  },
  "liveProof.proofSize": {
    en: "Proof size",
    uk: "Розмір доказу",
  },
  "liveProof.serverSide": {
    en: "server-side",
    uk: "на сервері",
  },
  "liveProof.clientSide": {
    en: "in your browser",
    uk: "у вашому браузері",
  },
  "liveProof.failed": {
    en: "Verification failed",
    uk: "Перевірка не пройшла",
  },
  "liveProof.scenario.label": {
    en: "Scenario",
    uk: "Сценарій",
  },
  "liveProof.reset": {
    en: "Reset",
    uk: "Скинути",
  },
  "liveProof.transportSize": {
    en: "Transport",
    uk: "Транспорт",
  },
  "liveProof.printQr": {
    en: "Print QR",
    uk: "Друк QR",
  },
  "liveProof.sizeComparison": {
    en: "Your proof compared to:",
    uk: "Ваш доказ порівняно з:",
  },
  "liveProof.yourProof": {
    en: "Your proof",
    uk: "Ваш доказ",
  },
  "liveProof.sizeNote": {
    en: "Cryptographic proof of age — smaller than a tweet, scannable from paper",
    uk: "Криптографічний доказ віку — менший за твіт, зчитується з паперу",
  },

  // ── Paper Contracts ───────────────────────────────────────────────────
  "paperContracts.title": {
    en: "Real-world application: Contracts without personal data",
    uk: "Реальне застосування: контракти без персональних даних",
  },
  "paperContracts.subtitle": {
    en: "Today, selling a car means handing over your full name, address, birth date, and ID number to a stranger. ZK proofs change that: every contractual condition is cryptographically proven without revealing any personal data.",
    uk: "Сьогодні продаж авто означає передачу повного імені, адреси, дати народження та номера документа незнайомцю. ZK-докази змінюють це: кожна умова контракту криптографічно доведена без розкриття персональних даних.",
  },
  "paperContracts.todayLabel": {
    en: "Today's paper contract",
    uk: "Сьогоднішній паперовий контракт",
  },
  "paperContracts.todayItems": {
    en: "Full name, address, birth date printed in plain text|Government ID number visible to the counterparty|No way to verify claims without calling authorities|Personal data sitting in filing cabinets forever",
    uk: "ПІБ, адреса, дата народження — відкритим текстом|Номер документа видно контрагенту|Неможливо перевірити дані без дзвінка в органи|Персональні дані лежать у шафах назавжди",
  },
  "paperContracts.zkLabel": {
    en: "With ZK proofs",
    uk: "З ZK-доказами",
  },
  "paperContracts.sellerProved": {
    en: "Seller: age \u2265 18, identity cryptographically bound to vehicle",
    uk: "Продавець: вік \u2265 18, особу криптографічно прив\u2019язано до ТЗ",
  },
  "paperContracts.vehicleProved": {
    en: "Vehicle: insurance valid, VIN not revoked",
    uk: "ТЗ: страховка дійсна, VIN не відкликано",
  },
  "paperContracts.buyerProved": {
    en: "Buyer: age \u2265 18",
    uk: "Покупець: вік \u2265 18",
  },
  "paperContracts.noNames": {
    en: "Zero personal data disclosed. Every condition machine-verifiable.",
    uk: "Жодних персональних даних. Кожна умова верифікується машиною.",
  },
  "paperContracts.courtResolution": {
    en: "Dispute? Court subpoenas the credential issuer by nullifier.\nThe issuer searches their database \u2014 finds the counterparty.\nIdentification is a judicial act, not a property of the document.",
    uk: "Спір? Суд запитує видавця посвідчень за нуліфікатором.\nВидавець перебирає свою базу \u2014 знаходить контрагента.\nІдентифікація \u2014 судова дія, а не властивість документу.",
  },
  "paperContracts.qrLabel": {
    en: "Real QR codes embedding compressed ZK proofs — scannable and verifiable offline",
    uk: "Справжні QR-коди з компресованими ZK-доказами — скануються та перевіряються офлайн",
  },
  "paperContracts.generating": {
    en: "Generating real proofs for vehicle sale contract...",
    uk: "Генерація реальних доказів для контракту купівлі-продажу ТЗ...",
  },
  "paperContracts.contractType": {
    en: "Vehicle Sale Contract",
    uk: "Договір купівлі-продажу ТЗ",
  },
  "paperContracts.zkAgreement": {
    en: "ZK-Verified Agreement",
    uk: "ZK-верифікований договір",
  },
  "paperContracts.cta": {
    en: "Try the Demo",
    uk: "Спробувати демо",
  },
  "paperContracts.isolationTitle": {
    en: "One Ringset to Rule Them All",
    uk: "Один набір схем, щоб керувати всіма",
  },
  "paperContracts.isolationDesc1": {
    en: "One set of ZK circuits. Every registry in the EU can verify against it. Civil registry, vehicle registry, university registry, health insurance \u2014 none of them talk to each other. None of them need to. The citizen carries the proof. The registries stay in their lanes.",
    uk: "Один набір ZK-схем. Кожен реєстр в ЄС може верифікувати проти нього. Цивільний реєстр, реєстр ТЗ, університетський реєстр, медичне страхування \u2014 жоден з них не спілкується з іншим. І не треба. Громадянин несе доказ. Реєстри залишаються у своїх смугах.",
  },
  "paperContracts.isolationDesc2": {
    en: "27 countries. 27 different IT systems. 27 different data protection laws. Zero bilateral integrations needed. A French citizen proves age to a German authority. France and Germany exchange exactly zero bytes. That\u2019s not a roadmap \u2014 that\u2019s nine Circom circuits and a compact proof.",
    uk: "27 країн. 27 різних ІТ-систем. 27 різних законів про захист даних. Нуль двосторонніх інтеграцій. Французький громадянин доводить вік німецькому відомству. Франція і Німеччина обмінюються рівно нулем байтів. Це не дорожня карта \u2014 це дев\u2019ять Circom-схем і компактний доказ.",
  },
  "paperContracts.isolationRegistry1": {
    en: "Civil Registry",
    uk: "Цивільний реєстр",
  },
  "paperContracts.isolationCitizen": {
    en: "Citizen",
    uk: "Громадянин",
  },
  "paperContracts.isolationRegistry2": {
    en: "Vehicle Registry",
    uk: "Реєстр ТЗ",
  },
  "paperContracts.isolationProofOnly": {
    en: "only proofs cross",
    uk: "лише докази",
  },

  // ── Learn More nav ───────────────────────────────────────────────────
  "nav.learn": { en: "Learn More", uk: "Дізнатися більше" },

  // ── Stats ───────────────────────────────────────────────────────────────
  "stats.circuits": { en: "Circom Circuits", uk: "Circom схеми" },
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
  "demo.subtitle": {
    en: "Zero-Knowledge Selective Disclosure for eIDAS 2.0 Credentials",
    uk: "Вибіркове розкриття з нульовим розголошенням для eIDAS 2.0 посвідчень",
  },
  "demo.step1Label": { en: "Issuer", uk: "Видавець" },
  "demo.step1Desc": { en: "Issue a verifiable credential", uk: "Видати верифіковане посвідчення" },
  "demo.step2Label": { en: "Schema", uk: "Схема" },
  "demo.step2Desc": { en: "Select predicates & generate proof", uk: "Обрати предикати та згенерувати доказ" },
  "demo.step3Label": { en: "Verifier", uk: "Верифікатор" },
  "demo.step3Desc": { en: "Zero-knowledge verification result", uk: "Результат верифікації з нульовим розголошенням" },
  "demo.step4Label": { en: "Print", uk: "Друк" },
  "demo.step4Desc": { en: "QR codes for offline verification", uk: "QR-коди для офлайн верифікації" },
  "demo.saveProof": { en: "Save Proof", uk: "Зберегти доказ" },

  // ── Tab labels ──────────────────────────────────────────────────────────
  "demo.tabPid": { en: "National ID (PID)", uk: "Національний ID (PID)" },
  "demo.tabDrivers": { en: "Driver\u2019s License", uk: "Водійське посвідчення" },
  "demo.tabDiploma": { en: "University Diploma", uk: "Диплом університету" },
  "demo.tabStudentId": { en: "Student Card", uk: "Студентський квиток" },
  "demo.tabVehicle": { en: "Vehicle Registration", uk: "Реєстрація ТЗ" },

  // ── Issuer titles per credential type ───────────────────────────────────
  "demo.issuerTitlePid": { en: "Credential Issuer \u2014 Diia", uk: "Видавець посвідчення \u2014 Дія" },
  "demo.issuerSubtitlePid": { en: "Ministry of Digital Transformation of Ukraine", uk: "Міністерство цифрової трансформації України" },
  "demo.issuerTitleDrivers": { en: "Credential Issuer \u2014 PPA", uk: "Видавець посвідчення \u2014 PPA" },
  "demo.issuerSubtitleDrivers": { en: "Police and Border Guard Board \u2014 Estonia", uk: "Поліцейсько-прикордонне управління \u2014 Естонія" },
  "demo.issuerTitleDiploma": { en: "Credential Issuer \u2014 Sorbonne Universit\u00e9", uk: "Видавець посвідчення \u2014 Сорбонна" },
  "demo.issuerSubtitleDiploma": { en: "Sorbonne Universit\u00e9 \u2014 France", uk: "Університет Сорбонни \u2014 Франція" },
  "demo.issuerTitleStudentId": { en: "Student Card Issuer \u2014 University of Warsaw", uk: "Видавець студентського квитка \u2014 Варшавський університет" },
  "demo.issuerSubtitleStudentId": { en: "Uniwersytet Warszawski \u2014 Poland", uk: "Uniwersytet Warszawski \u2014 Польща" },
  "demo.issuerTitleVehicle": { en: "Credential Issuer \u2014 KBA", uk: "Видавець посвідчення \u2014 KBA" },
  "demo.issuerSubtitleVehicle": { en: "Kraftfahrt-Bundesamt \u2014 Germany", uk: "Федеральне відомство автотранспорту \u2014 Німеччина" },
  "demo.issuerTitlePidDe": { en: "Bundesdruckerei", uk: "Bundesdruckerei" },
  "demo.issuerSubtitlePidDe": { en: "Federal Printing Office \u2014 Germany", uk: "Федеральна друкарня \u2014 Німеччина" },
  "demo.issuerTitleDriversUa": { en: "HSC MVS", uk: "ГСЦ МВС" },
  "demo.issuerSubtitleDriversUa": { en: "Main Service Centre of MIA \u2014 Ukraine", uk: "Головний сервісний центр МВС України" },
  "demo.issuerTitleStudentIdUa": { en: "Taras Shevchenko KNU", uk: "КНУ ім. Шевченка" },
  "demo.issuerSubtitleStudentIdUa": { en: "Taras Shevchenko National University \u2014 Ukraine", uk: "Київський національний університет ім. Тараса Шевченка" },
  "demo.issuerTitleDiplomaUa": { en: "Igor Sikorsky KPI", uk: "КПІ ім. Сікорського" },
  "demo.issuerSubtitleDiplomaUa": { en: "Igor Sikorsky Kyiv Polytechnic Institute \u2014 Ukraine", uk: "Київський політехнічний інститут ім. Ігоря Сікорського" },
  "demo.issuerTitleVehicleUa": { en: "MVS Ukraine", uk: "МВС України" },
  "demo.issuerSubtitleVehicleUa": { en: "Ministry of Internal Affairs \u2014 Ukraine", uk: "Міністерство внутрішніх справ України" },

  // ── Credential labels ──────────────────────────────────────────────────
  "demo.credLabelPid": { en: "Personal Identification Data (PID)", uk: "Персональні ідентифікаційні дані (PID)" },
  "demo.credLabelDrivers": { en: "EU Driver\u2019s License (mDL)", uk: "Водійське посвідчення ЄС (mDL)" },
  "demo.credLabelDiploma": { en: "University Diploma (EAA)", uk: "Диплом університету (EAA)" },
  "demo.credLabelStudentId": { en: "Student Card (EAA)", uk: "Студентський квиток (EAA)" },
  "demo.credLabelVehicle": { en: "Vehicle Registration Certificate", uk: "Свідоцтво про реєстрацію ТЗ" },

  // ── Field labels ───────────────────────────────────────────────────────
  "demo.fieldBirthDate": { en: "Date of Birth", uk: "Дата народження" },
  "demo.fieldAgeOver18": { en: "Age Over 18", uk: "Вік понад 18" },
  "demo.fieldIssuingCountry": { en: "Issuing Country", uk: "Країна видачі" },
  "demo.fieldGender": { en: "Gender", uk: "Стать" },
  "demo.fieldResidentCity": { en: "Resident City", uk: "Місто проживання" },
  "demo.fieldExpiryDate": { en: "Expiry Date", uk: "Дата закінчення" },
  "demo.predAgeOver18": { en: "Age confirmed (boolean)", uk: "Вік підтверджено (булеве)" },
  "demo.predAgeOver18Desc": { en: "Proves age_over_18 is true without revealing birthdate", uk: "Доводить, що age_over_18 є true без розкриття дати народження" },
  "demo.predIssuingCountry": { en: "Issuing country is in eIDAS zone", uk: "Країна видачі в зоні eIDAS" },
  "demo.predIssuingCountryDesc": { en: "Proves issuing country is an EU/eIDAS member", uk: "Доводить, що країна видачі є членом ЄС/eIDAS" },
  "demo.predDocValid": { en: "Document is not expired", uk: "Документ не прострочений" },
  "demo.predDocValidDesc": { en: "Proves expiry date is in the future", uk: "Доводить, що дата закінчення в майбутньому" },
  "demo.field.holderName": { en: "Holder Name", uk: "Ім'я власника" },
  "demo.field.category": { en: "Category", uk: "Категорія" },
  "demo.field.issueDate": { en: "Issue Date", uk: "Дата видачі" },
  "demo.field.expiryDate": { en: "Expiry Date", uk: "Дата закінчення" },
  "demo.field.restrictions": { en: "Restrictions", uk: "Обмеження" },
  "demo.field.licenseNumber": { en: "License Number", uk: "Номер посвідчення" },
  "demo.field.studentName": { en: "Student Name", uk: "Ім'я студента" },
  "demo.field.university": { en: "University", uk: "Університет" },
  "demo.field.degree": { en: "Degree", uk: "Ступінь" },
  "demo.field.fieldOfStudy": { en: "Field of Study", uk: "Спеціальність" },
  "demo.field.graduationYear": { en: "Graduation Year", uk: "Рік випуску" },
  "demo.field.diplomaNumber": { en: "Diploma Number", uk: "Номер диплома" },
  "demo.field.honors": { en: "Honors", uk: "Відзнака" },
  "demo.field.faculty": { en: "Faculty", uk: "Факультет" },
  "demo.field.enrollmentYear": { en: "Enrollment Year", uk: "Рік вступу" },
  "demo.field.validUntil": { en: "Valid Until", uk: "Дійсний до" },
  "demo.field.studentNumber": { en: "Student Number", uk: "Номер студентського квитка" },
  "demo.field.ownerName": { en: "Owner Name", uk: "Ім'я власника" },
  "demo.field.ownerDocNumber": { en: "Owner Document No.", uk: "Номер документа власника" },
  "demo.field.plateNumber": { en: "Plate Number", uk: "Номерний знак" },
  "demo.field.makeModel": { en: "Make & Model", uk: "Марка та модель" },
  "demo.field.vin": { en: "VIN", uk: "VIN" },
  "demo.field.insuranceExpiry": { en: "Insurance Expiry", uk: "Закінчення страховки" },
  "demo.field.registrationDate": { en: "Registration Date", uk: "Дата реєстрації" },

  // ── Predicate labels + descriptions ────────────────────────────────────
  "demo.predCategoryB": { en: "License includes category B", uk: "Посвідчення включає категорію B" },
  "demo.predCategoryBDesc": { en: "Proves category matches expected value", uk: "Доводить відповідність категорії очікуваному значенню" },
  "demo.predValid": { en: "License is valid (not expired)", uk: "Посвідчення дійсне (не прострочене)" },
  "demo.predValidDesc": { en: "Proves expiry date is in the future", uk: "Доводить, що дата закінчення в майбутньому" },
  "demo.predExperienced": { en: "Issued at least 2 years ago", uk: "Видано щонайменше 2 роки тому" },
  "demo.predExperiencedDesc": { en: "Proves driving experience of 2+ years", uk: "Доводить водійський досвід 2+ роки" },
  "demo.predNoRestrictions": { en: "No restrictions on license", uk: "Без обмежень на посвідченні" },
  "demo.predNoRestrictionsDesc": { en: "Proves restrictions field equals 'None'", uk: "Доводить, що поле обмежень дорівнює 'None'" },
  "demo.predStem": { en: "Field is in STEM", uk: "Спеціальність в STEM" },
  "demo.predStemDesc": { en: "Proves field of study is in STEM disciplines", uk: "Доводить, що спеціальність належить до STEM" },
  "demo.predRecentGrad": { en: "Graduated in 2020 or later", uk: "Закінчив у 2020 або пізніше" },
  "demo.predRecentGradDesc": { en: "Proves graduation year >= 2020", uk: "Доводить рік випуску >= 2020" },
  "demo.predMasters": { en: "Holds a Master's degree", uk: "Має ступінь магістра" },
  "demo.predMastersDesc": { en: "Proves degree is Master or PhD level", uk: "Доводить ступінь магістра або PhD" },
  "demo.predUniversityMatch": { en: "University matches value", uk: "Університет відповідає значенню" },
  "demo.predUniversityMatchDesc": { en: "Proves university equals expected value", uk: "Доводить, що університет дорівнює очікуваному" },
  "demo.predActiveStudent": { en: "Student card is valid", uk: "Студентський квиток дійсний" },
  "demo.predActiveStudentDesc": { en: "Proves the student card has not expired", uk: "Доводить, що студентський квиток не прострочений" },
  "demo.predEnrolledRecently": { en: "Enrolled in 2020 or later", uk: "Вступив у 2020 або пізніше" },
  "demo.predEnrolledRecentlyDesc": { en: "Proves enrollment year is 2020 or later", uk: "Доводить, що рік вступу — 2020 або пізніше" },
  "demo.predInsured": { en: "Vehicle is insured (not expired)", uk: "ТЗ застраховано (не прострочено)" },
  "demo.predInsuredDesc": { en: "Proves insurance expiry date is in the future", uk: "Доводить, що страховка не закінчилась" },
  "demo.predEuType": { en: "Make is EU type-approved", uk: "Марка сертифікована в ЄС" },
  "demo.predEuTypeDesc": { en: "Proves vehicle make is in EU type-approved list", uk: "Доводить, що марка авто в списку сертифікованих ЄС" },
  "demo.predVinActive": { en: "VIN not revoked", uk: "VIN не відкликано" },
  "demo.predVinActiveDesc": { en: "Proves VIN is not in revocation registry", uk: "Доводить, що VIN не в реєстрі відкликань" },

  "demo.issuerTitle": {
    en: "Credential Issuer \u2014 Diia",
    uk: "Видавець посвідчення \u2014 Дія",
  },
  "demo.issuerSubtitle": {
    en: "Ministry of Digital Transformation of Ukraine \u2014 PID Credential Example",
    uk: "Міністерство цифрової трансформації України \u2014 приклад PID посвідчення",
  },
  "demo.pidLabel": {
    en: "Personal Identification Data (PID) \u2014 one of many eIDAS 2.0 credential types",
    uk: "Персональні ідентифікаційні дані (PID) \u2014 один з багатьох типів eIDAS 2.0 посвідчень",
  },
  "demo.fieldGivenName": { en: "Given Name", uk: "Ім'я" },
  "demo.fieldFamilyName": { en: "Family Name", uk: "Прізвище" },
  "demo.fieldBirthdate": { en: "Date of Birth", uk: "Дата народження" },
  "demo.fieldNationality": { en: "Nationality", uk: "Громадянство" },
  "demo.fieldResidentCountry": {
    en: "Resident Country",
    uk: "Країна проживання",
  },
  "demo.fieldDocNumber": { en: "Document Number", uk: "Номер документа" },
  "demo.fieldIssuingAuthority": {
    en: "Issuing Authority",
    uk: "Орган видачі",
  },
  "demo.issuing": {
    en: "Issuing Credential...",
    uk: "Видача посвідчення...",
  },
  "demo.issueBtn": {
    en: "Issue Credential",
    uk: "Видати посвідчення",
  },
  "demo.issuingShort": { en: "Issuing...", uk: "Видача..." },
  "demo.pidCredential": { en: "PID Credential", uk: "PID посвідчення" },
  "demo.digitalCredential": {
    en: "Digital Credential",
    uk: "Цифрове посвідчення",
  },
  "demo.sdjwtVc": {
    en: "SD-JWT Verifiable Credential",
    uk: "SD-JWT верифіковане посвідчення",
  },
  "demo.sdjwtTooltip": {
    en: "A Selective Disclosure JSON Web Token. Each claim can be independently revealed or hidden.",
    uk: "Selective Disclosure JSON Web Token. Кожне твердження може бути незалежно розкрите або приховане.",
  },
  "demo.selectClaims": {
    en: "Select Claims to Prove",
    uk: "Оберіть дані для доведення",
  },
  "demo.selectClaimsSub": {
    en: "Choose predicates for zero-knowledge proof",
    uk: "Оберіть предикати для доказу з нульовим розголошенням",
  },
  "demo.predicateTooltip": {
    en: "A yes/no condition checked inside the ZK circuit, e.g. 'age >= 18'. The verifier learns only that the condition holds.",
    uk: "Умова так/ні, що перевіряється всередині ZK схеми, напр. 'вік >= 18'. Верифікатор дізнається лише, що умова виконана.",
  },
  "demo.predAge": {
    en: "I am at least 18 years old",
    uk: "Мені щонайменше 18 років",
  },
  "demo.predAgeDesc": {
    en: "Proves age >= 18 without revealing birthdate",
    uk: "Доводить вік >= 18 без розкриття дати народження",
  },
  "demo.predNat": {
    en: "My nationality is in the eIDAS zone",
    uk: "Моє громадянство — в зоні eIDAS",
  },
  "demo.predNatDesc": {
    en: "Proves eIDAS zone membership without revealing country",
    uk: "Доводить членство в зоні eIDAS без розкриття країни",
  },
  "demo.predName": {
    en: "My name matches a specific value",
    uk: "Моє ім'я збігається з конкретним значенням",
  },
  "demo.predNameDesc": {
    en: "Proves name equality without revealing it in plaintext",
    uk: "Доводить рівність імені без розкриття його у відкритому вигляді",
  },
  "demo.predAgeLte": {
    en: "I am at most 65 years old",
    uk: "Мені не більше 65 років",
  },
  "demo.predAgeLteDesc": {
    en: "Proves age <= 65 without revealing birthdate",
    uk: "Доводить вік <= 65 без розкриття дати народження",
  },
  "demo.predNotRevoked": {
    en: "My credential is not revoked",
    uk: "Моє посвідчення не відкликане",
  },
  "demo.predNotRevokedDesc": {
    en: 'Proves document number is not "REVOKED"',
    uk: 'Доводить, що номер документа не "REVOKED"',
  },
  "demo.predAgeRange": {
    en: "My age is between 18 and 65",
    uk: "Мій вік від 18 до 65 років",
  },
  "demo.predAgeRangeDesc": {
    en: "Proves age is between 18 and 65 in a single circuit",
    uk: "Доводить, що вік від 18 до 65 в одній схемі",
  },
  "demo.proofMode": { en: "Proof Mode", uk: "Режим доказу" },
  "demo.proofModeTooltip": {
    en: "Individual proofs are verified separately. Compound proofs combine multiple predicates with AND/OR logic into a single proof.",
    uk: "Індивідуальні докази перевіряються окремо. Складені докази об'єднують кілька предикатів за логікою AND/OR в один доказ.",
  },
  "demo.modeIndividual": { en: "Individual", uk: "Індивідуальний" },
  "demo.modeIndividualDesc": {
    en: "Separate proof per predicate",
    uk: "Окремий доказ на предикат",
  },
  "demo.modeAndDesc": { en: "All must hold", uk: "Усі мають виконуватись" },
  "demo.modeOrDesc": {
    en: "At least one must hold",
    uk: "Щонайменше один має виконуватись",
  },
  "demo.modeExplainIndividual": {
    en: "Each predicate generates a separate proof",
    uk: "Кожен предикат генерує окремий доказ",
  },
  "demo.modeExplainAnd": {
    en: "Single compound proof \u2014 ALL predicates must be true",
    uk: "Один складений доказ \u2014 УСІ предикати мають бути істинними",
  },
  "demo.modeExplainDocNumber": {
    en: "Locked to AND \u2014 document number binds all predicates to one credential.",
    uk: "Зафіксовано AND \u2014 номер документа прив'язує всі предикати до одного посвідчення.",
  },
  "demo.modeUnlock": {
    en: "Disable document disclosure to unlock.",
    uk: "Вимкніть розкриття документа для розблокування.",
  },
  "demo.printRequiresAnd": {
    en: "Paper proofs require AND mode with document number disclosure for holder binding.",
    uk: "Паперові докази потребують режим AND з розкриттям номера документа для прив'язки до власника.",
  },
  "demo.modeExplainOr": {
    en: "Single compound proof \u2014 AT LEAST ONE predicate must be true",
    uk: "Один складений доказ \u2014 ЩОНАЙМЕНШЕ ОДИН предикат має бути істинним",
  },
  "demo.nullifierScope": {
    en: "Nullifier Scope",
    uk: "Скоп нуліфікатора",
  },
  "demo.nullifierTooltip": {
    en: "A deterministic hash scoped to a context. Same credential + same scope = same nullifier, enabling double-spend detection.",
    uk: "Детермінований хеш, прив'язаний до контексту. Те саме посвідчення + той самий скоп = той самий нуліфікатор, що дозволяє виявити подвійне використання.",
  },
  "demo.optional": { en: "(optional)", uk: "(необов'язково)" },
  "demo.discloseDocNumber": {
    en: "Disclose document number",
    uk: "Розкрити номер документа",
  },
  "demo.discloseDocNumberDesc": {
    en: "Include the document number in plaintext so the verifier can cross-reference it against a physical ID. Recommended for paper proofs.",
    uk: "Включити номер документа у відкритому вигляді, щоб верифікатор міг звірити його з фізичним документом. Рекомендовано для паперових доказів.",
  },
  "demo.docNumberWarning": {
    en: "Without a disclosed document number, a paper proof cannot be tied to a specific person. The verifier will have no way to confirm who the credential belongs to.",
    uk: "Без розкритого номера документа паперовий доказ не може бути прив'язаний до конкретної особи. Верифікатор не зможе підтвердити, кому належить посвідчення.",
  },
  "demo.disclosed": {
    en: "disclosed",
    uk: "розкрито",
  },
  "demo.nullifierDesc": {
    en: "Generates a deterministic nullifier for double-spend detection. Same scope = same nullifier.",
    uk: "Генерує детермінований нуліфікатор для виявлення подвійного використання. Той самий скоп = той самий нуліфікатор.",
  },
  "demo.generating": {
    en: "Generating cryptographic proof... ",
    uk: "Генерація криптографічного доказу... ",
  },
  "demo.generatingDesc": {
    en: "Real ECDSA signature verification + zero-knowledge circuit execution in progress",
    uk: "Реальна перевірка ECDSA підпису + виконання схеми з нульовим розголошенням",
  },
  "demo.proofGenerated": {
    en: "Proof generated successfully",
    uk: "Доказ успішно згенеровано",
  },
  "demo.backToIssuer": {
    en: "\u2190 Back to Issuer",
    uk: "\u2190 Назад до видавця",
  },
  "demo.generatingShort": { en: "Generating...", uk: "Генерація..." },
  "demo.proofGeneratedBtn": {
    en: "Proof Generated",
    uk: "Доказ згенеровано",
  },
  "demo.generateBtn": {
    en: "Generate ZK Proof",
    uk: "Згенерувати доказ з НР",
  },
  "demo.generateBrowserBtn": {
    en: "Prove in Browser (snarkjs)",
    uk: "Довести у браузері (snarkjs)",
  },
  "demo.browserHint": {
    en: "Browser proving requires a lightweight witness endpoint (coming soon). ECDSA signature verification (~2M constraints) runs server-side; only predicate circuits (~300 constraints) can prove in-browser.",
    uk: "Доведення у браузері потребує легковагий ендпоінт для свідка (незабаром). Верифікація підпису ECDSA (~2M обмежень) виконується на сервері; лише предикатні схеми (~300 обмежень) можуть працювати у браузері.",
  },
  "demo.verifierTitle": {
    en: "Service Provider \u2014 Verification Portal",
    uk: "Постачальник послуг \u2014 Портал верифікації",
  },
  "demo.verifierSubtitle": {
    en: "Zero-Knowledge Proof Verification",
    uk: "Верифікація доказу з нульовим розголошенням",
  },
  "demo.receivedArtifact": {
    en: "Received Proof Artifact",
    uk: "Отриманий артефакт доказу",
  },
  "demo.opaqueNote": {
    en: "Opaque cryptographic artifact \u2014 no credential data visible to verifier",
    uk: "Непрозорий криптографічний артефакт \u2014 дані посвідчення не видимі верифікатору",
  },
  "demo.verifyServer": {
    en: "Verify on Server",
    uk: "Перевірити на сервері",
  },
  "demo.verifyServerBoring": {
    en: "or verify on server, if you\u2019re old school",
    uk: "або перевірити на сервері, якщо ви старої школи",
  },
  "demo.verifyWasm": {
    en: "Verify right here, in your browser",
    uk: "Перевірити прямо тут, у вашому браузері",
  },
  "demo.wasmUnavailable": { en: "WASM Unavailable", uk: "WASM недоступний" },
  "demo.verifyingShort": { en: "Verifying...", uk: "Перевірка..." },
  "demo.autoVerifying": { en: "Verifying proof in your browser...", uk: "Верифікація доказу у вашому браузері..." },
  "demo.verificationResults": {
    en: "Verification Results",
    uk: "Результати верифікації",
  },
  "demo.verifiedServer": {
    en: "Verified server-side",
    uk: "Перевірено на сервері",
  },
  "demo.verifiedServerTooltip": {
    en: "Proof verified on the server using Groth16 (ark-circom). Per-circuit trusted setup via .zkey files.",
    uk: "Доказ перевірено на сервері за допомогою Groth16 (ark-circom). Довірена ініціалізація для кожної схеми через .zkey файли.",
  },
  "demo.verifiedWasm": {
    en: "Verified client-side (WASM)",
    uk: "Перевірено на клієнті (WASM)",
  },
  "demo.verifiedWasmTooltip": {
    en: "Proof verified entirely in your browser using WebAssembly. No data sent to any server.",
    uk: "Доказ перевірено повністю у вашому браузері за допомогою WebAssembly. Дані не відправлено на жоден сервер.",
  },
  "demo.verified": { en: "Verified", uk: "Перевірено" },
  "demo.notDisclosed": { en: "Not Disclosed", uk: "Не розкрито" },
  "demo.nullifierChecking": {
    en: "Checking nullifier registry...",
    uk: "Перевірка реєстру нуліфікаторів...",
  },
  "demo.doubleSpend": {
    en: "DOUBLE-SPEND DETECTED \u2014 This proof was already used",
    uk: "ВИЯВЛЕНО ПОДВІЙНЕ ВИКОРИСТАННЯ \u2014 Цей доказ вже був використаний",
  },
  "demo.firstUse": {
    en: "First use \u2014 Nullifier registered",
    uk: "Перше використання \u2014 Нуліфікатор зареєстровано",
  },
  "demo.registryCount": { en: "recorded", uk: "записано" },
  "demo.privacyBanner": {
    en: "The verifier learned NOTHING about the credential holder — only the document number (as a public anchor) and that these predicates are true.",
    uk: "Верифікатор не дізнався НІЧОГО про власника посвідчення — лише номер документа (як публічний ідентифікатор) та що ці предикати істинні.",
  },
  "demo.zkTitle": {
    en: "How it works: from your data to a proof",
    uk: "Як це працює: від ваших даних до доказу",
  },
  "demo.zkSubtitle": {
    en: "Your personal data never leaves your device. Only a mathematical proof is shared.",
    uk: "Ваші персональні дані ніколи не покидають ваш пристрій. Передається лише математичний доказ.",
  },
  "demo.zkStep1Title": {
    en: "Your ID document",
    uk: "Ваш документ",
  },
  "demo.zkStep1Desc": {
    en: "This data is private. Only you can see it.",
    uk: "Ці дані приватні. Бачите їх лише ви.",
  },
  "demo.zkStep2Title": {
    en: "Each question is checked, then the data is destroyed",
    uk: "Кожне питання перевіряється, а потім дані знищуються",
  },
  "demo.zkStep2Desc": {
    en: "A program reads your real value, checks if the condition is true, and outputs only \u201Cyes\u201D or \u201Cno\u201D. The actual value is never stored or sent anywhere.",
    uk: "Програма зчитує ваше реальне значення, перевіряє чи умова істинна, і видає лише \u201Cтак\u201D або \u201Cні\u201D. Фактичне значення ніколи не зберігається і нікуди не відправляється.",
  },
  "demo.zkRealValue": { en: "real value", uk: "реальне значення" },
  "demo.zkOnlyAnswer": { en: "only yes/no leaves", uk: "виходить лише так/ні" },
  "demo.zkStep2Note": {
    en: "The government\u2019s digital signature is checked inside the proof, so nobody can fake the answer.",
    uk: "Цифровий підпис уряду перевіряється всередині доказу, тому ніхто не може підробити відповідь.",
  },
  "demo.zkStep3Title": {
    en: "What the verifier actually receives",
    uk: "Що насправді отримує верифікатор",
  },
  "demo.zkStep3Desc": {
    en: "Only the proven facts. Everything else is invisible.",
    uk: "Лише доведені факти. Все інше невидиме.",
  },
  "demo.zkProfileToggle": {
    en: "\u25B6 Show WASM execution profile",
    uk: "\u25B6 Показати профіль виконання WASM",
  },
  "demo.zkProfileVk": { en: "VK decode", uk: "Декодування VK" },
  "demo.zkProfileParse": { en: "Proof parse", uk: "Парсинг доказу" },
  "demo.zkProfileInit": { en: "WASM engine", uk: "рушій WASM" },
  "demo.zkProfileVerify": { en: "Pairing check", uk: "Перевірка пейрингу" },
  "demo.zkProfileTotal": { en: "Total", uk: "Загалом" },
  "demo.zkProfileProof": { en: "Proof", uk: "Доказ" },
  "demo.zkProfileWasmInit": { en: "WASM initialization (once per page load)", uk: "Ініціалізація WASM (раз за завантаження сторінки)" },
  "demo.zkProfileJsImport": { en: "JS module load", uk: "Завантаження JS" },
  "demo.zkProfileWasmBoot": { en: "WASM + CRS init", uk: "WASM + CRS ініц." },
  "demo.proofExport": { en: "Proof Export", uk: "Експорт доказу" },
  "demo.cborTooltip": {
    en: "Concise Binary Object Representation. A compact binary format for portable proof envelopes.",
    uk: "Concise Binary Object Representation. Компактний бінарний формат для портативних конвертів доказів.",
  },
  "demo.cborBinaryTooltip": {
    en: "Downloads the proof as a CBOR binary file — portable, offline-verifiable.",
    uk: "Завантажує доказ як бінарний CBOR файл — портативний, верифікується офлайн.",
  },
  "demo.encoding": { en: "Encoding...", uk: "Кодування..." },
  "demo.exportCbor": { en: "Export as CBOR", uk: "Експортувати як CBOR" },
  "demo.exportCompoundCbor": { en: "Export Compound Proof as CBOR", uk: "Експортувати складений доказ у CBOR" },
  "demo.cborDesc": {
    en: "CBOR-encoded proof envelope. Portable binary format for offline verification.",
    uk: "Конверт доказу в форматі CBOR. Портативний бінарний формат для офлайн верифікації.",
  },
  "demo.downloadCbor": { en: "Download .cbor", uk: "Завантажити .cbor" },
  "demo.saveCbor": { en: "Save .cbor", uk: "Зберегти .cbor" },
  "demo.printProof": { en: "Generate Certificate", uk: "Сформувати засвідчення" },
  "demo.revocationTitle": {
    en: "Credential Revocation",
    uk: "Відкликання посвідчення",
  },
  "demo.revoked": { en: "Revoked", uk: "Відкликано" },
  "demo.revokeDesc": {
    en: "Issuer can revoke credential using the Sparse Merkle Tree registry.",
    uk: "Видавець може відкликати посвідчення за допомогою реєстру розрідженого дерева Меркла.",
  },
  "demo.revokeTooltip": {
    en: "Adds the credential ID to the Sparse Merkle Tree revocation registry. After revocation, proofs using this credential will fail the revocation check.",
    uk: "Додає ID посвідчення до реєстру відкликань на основі розрідженого дерева Меркла. Після відкликання докази з цим посвідченням не пройдуть перевірку.",
  },
  "demo.revoking": { en: "Revoking...", uk: "Відкликання..." },
  "demo.revokeBtn": {
    en: "Revoke This Credential",
    uk: "Відкликати це посвідчення",
  },
  "demo.credentialRevoked": {
    en: "Credential revoked",
    uk: "Посвідчення відкликано",
  },
  "demo.revocationRoot": {
    en: "Revocation Root (SMT)",
    uk: "Корінь відкликання (SMT)",
  },
  "demo.currentRevRoot": {
    en: "Current Revocation Root",
    uk: "Поточний корінь відкликання",
  },
  "demo.fetchingRoot": {
    en: "Fetching...",
    uk: "Завантаження...",
  },
  "demo.openid4vpTitle": {
    en: "OpenID4VP Presentation Request",
    uk: "OpenID4VP запит презентації",
  },
  "demo.openid4vpDesc": {
    en: "Generate an OpenID4VP-compatible PresentationDefinition that wallets can consume.",
    uk: "Згенерувати PresentationDefinition, сумісний з OpenID4VP, який гаманці можуть обробити.",
  },
  "demo.openid4vpGenerating": { en: "Generating...", uk: "Генерація..." },
  "demo.openid4vpBtn": {
    en: "Generate Presentation Request",
    uk: "Згенерувати запит презентації",
  },
  "demo.presReqAddReq": { en: "Add Requirement", uk: "Додати вимогу" },
  "demo.presReqRemove": { en: "Remove", uk: "Видалити" },
  "demo.presReqClaim": { en: "Claim", uk: "Поле" },
  "demo.presReqOp": { en: "Operation", uk: "Операція" },
  "demo.presReqValue": { en: "Value", uk: "Значення" },
  "demo.presReqEmpty": { en: "Add at least one requirement", uk: "Додайте хоча б одну вимогу" },
  "demo.startOver": { en: "Start Over", uk: "Почати спочатку" },

  // ── On-device proving progress ──────────────────────────────────────────
  "prove.cachingZkey": { en: "Caching zkey sections...", uk: "Кешування секцій zkey..." },
  "prove.downloadingChunk": { en: "Downloading chunk", uk: "Завантаження фрагменту" },
  "prove.cachedChunk": { en: "Cached", uk: "Збережено" },
  "prove.loadingWasm": { en: "Loading WASM module...", uk: "Завантаження WASM модуля..." },
  "prove.parsingClaim": { en: "Parsing claim on device...", uk: "Обробка атрибуту на пристрої..." },
  "prove.ecdsaProof": { en: "ECDSA proof (1.2 GB download on first run)...", uk: "ECDSA доказ (1.2 ГБ завантаження при першому запуску)..." },
  "prove.downloadingWasm": { en: "Downloading WASM...", uk: "Завантаження WASM..." },
  "prove.generatingProof": { en: "Generating proof...", uk: "Генерація доказу..." },
  "prove.verifyingProof": { en: "Verifying proof...", uk: "Верифікація доказу..." },
  "prove.predicate": { en: "Predicate", uk: "Предикат" },
  "prove.allDone": { en: "All proofs generated in", uk: "Усі докази згенеровано за" },

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
  "cred.proofSize": { en: "ZK proof: 2.1 KB", uk: "ZK: 2.1 КБ" },
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
    en: "Drop a .cbor proof envelope to verify it entirely in your browser. No data is sent to any server \u2014 verification uses trusted VKs and WASM.",
    uk: "Перетягніть .cbor конверт доказу для верифікації повністю у вашому браузері. Дані не відправляються на жоден сервер \u2014 верифікація використовує довірені VK та WASM.",
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
    en: "Add this page to your home screen to install it as an app. Once installed, you can scan and verify paper proofs without internet — everything runs on your device.",
    uk: "Додайте цю сторінку на головний екран, щоб встановити як застосунок. Після встановлення ви зможете сканувати та перевіряти паперові докази без інтернету — все працює на вашому пристрої.",
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
    en: "Verify All (WASM)",
    uk: "Перевірити все (WASM)",
  },
  "verify.initWasm": {
    en: "Initializing WASM...",
    uk: "Ініціалізація WASM...",
  },
  "verify.verifyingBrowser": {
    en: "Verifying in browser...",
    uk: "Перевірка в браузері...",
  },
  "verify.allVerified": {
    en: "All proofs verified client-side. No data was sent to any server.",
    uk: "Всі докази перевірено на клієнті. Дані не відправлено на жоден сервер.",
  },
  "verify.vkNote": {
    en: "Verification keys derived from trusted circuit bytecode at build time.",
    uk: "Ключі верифікації виведено з довіреного байткоду схеми під час збірки.",
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
    en: "VERIFY PARTY IDENTITY",
    uk: "ПЕРЕВІРИТИ ОСОБУ СТОРОНИ",
  },
  "verify.documentNumber": {
    en: "Document number",
    uk: "Номер документа",
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
  "contracts.verifying": { en: "Verifying…", uk: "Перевірка…" },
  "contracts.verified": { en: "All predicates verified", uk: "Всі предикати перевірені" },
  "contracts.verifyFailed": { en: "Verification failed", uk: "Перевірка не вдалася" },
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
