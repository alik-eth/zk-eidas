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
    en: "Prove who you are without revealing who you are",
    uk: "Доведіть, хто ви є, не розкриваючи хто ви є",
  },
  "hero.tagline": {
    en: "EU digital IDs expose your data every time you show them. We wrap them in zero-knowledge proofs — so you prove facts (\"I'm 18+\") without sharing personal details.",
    uk: "Цифрові ID ЄС розкривають ваші дані щоразу, коли ви їх показуєте. Ми загортаємо їх у ZK-докази — ви доводите факти («мені є 18»), не ділячись персональними даними.",
  },
  "hero.tryDemo": { en: "Try the Demo", uk: "Спробувати демо" },
  "hero.viewGithub": { en: "View on GitHub", uk: "Переглянути на GitHub" },

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

  // ── Solution ─────────────────────────────────────────────────────────
  "solution.title": {
    en: "How it works",
    uk: "Як це працює",
  },
  "solution.subtitle": {
    en: "A privacy layer on top of existing EU credentials. Nothing changes for governments or businesses — only the citizen gets new superpowers.",
    uk: "Шар приватності поверх існуючих посвідчень ЄС. Нічого не змінюється для урядів чи бізнесу — лише громадянин отримує нові суперсили.",
  },
  "solution.step1Title": {
    en: "Government issues credential",
    uk: "Держава видає посвідчення",
  },
  "solution.step1Desc": {
    en: "Exactly as today. Standard digital ID, signed the usual way. No changes needed.",
    uk: "Як і сьогодні. Стандартний цифровий ID, підписаний звичайним чином. Без змін.",
  },
  "solution.step1Label": {
    en: "nothing changes",
    uk: "нічого не змінюється",
  },
  "solution.step2Title": {
    en: "You create a proof",
    uk: "Ви створюєте доказ",
  },
  "solution.step2Desc": {
    en: "Your phone wraps the credential in a ZK proof. Only the answer leaves — \"yes, I'm 18+\" — never the actual birthdate.",
    uk: "Ваш телефон загортає посвідчення в ZK-доказ. Виходить лише відповідь — «так, мені є 18» — ніколи справжня дата народження.",
  },
  "solution.step3Title": {
    en: "Anyone can verify",
    uk: "Будь-хто може перевірити",
  },
  "solution.step3Desc": {
    en: "Verification takes milliseconds, works offline, and reveals zero personal data. A QR code on paper is enough.",
    uk: "Верифікація за мілісекунди, працює офлайн і не розкриває жодних персональних даних. QR-коду на папері достатньо.",
  },

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
  "learn.tocEscrow": { en: "Escrow", uk: "Ескроу" },
  "learn.tocAttestation": { en: "Attestation", uk: "Атестація" },
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
  "learn.whyZkSoundnessDesc": { en: "Invalid credentials cannot produce valid proofs. Fabrication is computationally infeasible under standard cryptographic assumptions.", uk: "Недійсні посвідчення не можуть створити дійсні докази. Фабрикація обчислювально нездійсненна за стандартних криптографічних припущень." },
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
  "learn.compFormatZk": { en: "Native mdoc", uk: "Нативний mdoc" },
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
  "learn.trustGapZk1": { en: "COSE signature verification runs natively inside the Longfellow proving system alongside the predicate.", uk: "Перевірка підпису COSE відбувається нативно всередині системи доведення Longfellow разом з предикатом." },
  "learn.trustGapZk2": { en: "The prover re-derives the credential digest and checks it against the issuer's COSE_Sign1 payload.", uk: "Довідник повторно обчислює дайджест посвідчення та перевіряє його проти COSE_Sign1 payload видавця." },
  "learn.trustGapZk3": { en: "Fabrication is computationally infeasible — the proof covers the entire chain:", uk: "Фабрикація обчислювально нездійсненна — доказ покриває весь ланцюг:" },
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
  "learn.howInputLabel": { en: "mdoc", uk: "mdoc" },
  "learn.howCredential": { en: "Credential", uk: "Посвідчення" },
  "learn.howParser": { en: "Parser", uk: "Парсер" },
  "learn.howParserSub": { en: "Claims + Key", uk: "Поля + Ключ" },
  "learn.howWitness": { en: "Witness", uk: "Свідок" },
  "learn.howWitnessSub": { en: "Circuit Inputs", uk: "Входи схеми" },
  "learn.howCircuit": { en: "Circuit", uk: "Схема" },
  "learn.howCircuitSub": { en: "COSE + Predicate", uk: "COSE + Предикат" },
  "learn.howProof": { en: "Proof", uk: "Доказ" },
  "learn.howProofSub": { en: "Sumcheck + Ligero", uk: "Sumcheck + Ligero" },
  "learn.howVerifier": { en: "Verifier", uk: "Верифікатор" },
  "learn.howVerifierSub": { en: "Pass / Fail", uk: "Так / Ні" },
  "learn.howStep1Title": { en: "Parse", uk: "Розбір" },
  "learn.howStep1Desc": { en: "Extract individual claims and the issuer's public key from the mdoc credential (ISO 18013-5). SD-JWT is not currently supported by Longfellow.", uk: "Витягнути окремі поля та публічний ключ видавця з посвідчення mdoc (ISO 18013-5). SD-JWT наразі не підтримується Longfellow." },
  "learn.howStep2Title": { en: "Witness", uk: "Свідок" },
  "learn.howStep2Desc": { en: "Convert claim values to circuit inputs: dates become integers, strings become hashes.", uk: "Конвертувати значення полів у входи схеми: дати стають цілими числами, рядки — хешами." },
  "learn.howStep3Title": { en: "Circuit", uk: "Схема" },
  "learn.howStep3Desc": { en: "Verify the COSE signature and evaluate the predicate in a single Longfellow execution.", uk: "Перевірити підпис COSE та обчислити предикат за одне виконання Longfellow." },
  "learn.howStep4Title": { en: "Prove", uk: "Доведення" },
  "learn.howStep4Desc": { en: "Generate a Sumcheck+Ligero proof (~3 seconds on server). No trusted setup required.", uk: "Згенерувати Sumcheck+Ligero доказ (~3 секунди на сервері). Довірена ініціалізація не потрібна." },
  "learn.howStep5Title": { en: "Verify", uk: "Верифікація" },
  "learn.howStep5Desc": { en: "Check the proof on server (<100ms), or verify the QEAA attestation offline via TSP signature.", uk: "Перевірити доказ на сервері (<100мс), або верифікувати QEAA атестацію офлайн через підпис TSP." },
  "learn.howMetricSize": { en: "proof size", uk: "розмір доказу" },
  "learn.howMetricVerify": { en: "verification", uk: "верифікація" },
  "learn.howMetricOffline": { en: "Offline", uk: "Офлайн" },
  "learn.howMetricOfflineDesc": { en: "via QEAA attestation", uk: "через QEAA атестацію" },
  "learn.howMetricDevice": { en: "Server-side", uk: "Серверне" },
  "learn.howMetricDeviceDesc": { en: "C++ prover, no WASM", uk: "C++ довідник, без WASM" },

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

  // 6b. Identity Escrow
  "learn.escrowTitle": { en: "Identity Escrow for Persistent Documents", uk: "Ідентіті ескроу для постійних документів" },
  "learn.escrowSubtitle": {
    en: "ZK proofs remove personal data from documents. But if parties are anonymous \u2014 how do you protect your rights in court? Identity escrow solves this: data is encrypted in the proof, decryption is only possible by a chosen escrow authority per established procedure.",
    uk: "ZK-докази видаляють персональні дані з документів. Але якщо сторони анонімні \u2014 як захистити свої права в суді? Ідентіті ескроу вирішує це: дані зашифровані в доказі, розшифровка можлива тільки обраним ескроу-органом за встановленою процедурою.",
  },
  "learn.escrowHowTitle": { en: "How it works", uk: "Як це працює" },
  "learn.escrowHowIntro": {
    en: "At signing, each party:",
    uk: "При підписанні кожна сторона:",
  },
  "learn.escrowStep1": {
    en: "Packs their data (name, address, document number) into field elements",
    uk: "Пакує свої дані (ім\u2019я, адреса, номер документа) в елементи поля",
  },
  "learn.escrowStep2": {
    en: "Derives a symmetric key K deterministically from wallet secret and contract hash",
    uk: "Виводить симетричний ключ K детерміновано з секрету гаманця та хешу контракту",
  },
  "learn.escrowStep3": {
    en: "Generates a single ZK proof that simultaneously: verifies the government credential signature (ECDSA P-256 in-circuit), computes a nullifier binding identity to contract, encrypts credential data with symmetric cipher inside the circuit, commits to key K via hash commitment",
    uk: "Генерує єдиний ZK-доказ, який одночасно: верифікує підпис державного посвідчення (ECDSA P-256 в схемі), обчислює нуліфікатор, що прив\u2019язує особу до контракту, шифрує дані посвідчення симетричним шифром всередині схеми, комітить ключ K через хеш-комітмент",
  },
  "learn.escrowStep4": {
    en: "Encrypts K under the escrow authority\u2019s ML-KEM-768 key (post-quantum safe, NIST FIPS 203)",
    uk: "Шифрує K під ML-KEM-768 ключем ескроу-органу (постквантово стійкий, NIST FIPS 203)",
  },
  "learn.escrowStep5": {
    en: "Counterparty verifies the proof and confirms key commitment before co-signing",
    uk: "Контрагент верифікує доказ і підтверджує комітмент ключа перед підписанням",
  },
  "learn.escrowHonestTitle": { en: "Why encryption is honest", uk: "Чому шифрування чесне" },
  "learn.escrowHonestDesc": {
    en: "Encryption happens inside the ZK circuit \u2014 the same one that verifies the issuer\u2019s signature. A party cannot encrypt garbage because the proof binds ciphertext to government-signed data. After decryption, the data hash must match the proof\u2019s public output.",
    uk: "Шифрування відбувається всередині ZK-схеми \u2014 тієї самої, що верифікує підпис видавця. Сторона не може зашифрувати сміття, бо доказ прив\u2019язує шифротекст до даних, підписаних державою. Після розшифровки хеш даних повинен збігатися з публічним виходом доказу.",
  },
  "learn.escrowPluggableTitle": { en: "Pluggable escrow authority", uk: "Підключаємий ескроу-орган" },
  "learn.escrowPluggableDesc": {
    en: "The escrow authority is a contract parameter \u2014 like jurisdiction or arbitration clause. Both parties agree at signing. In production, the authority\u2019s ML-KEM seed is stored in an HSM with key rotation policy.",
    uk: "Ескроу-орган \u2014 це параметр контракту, як юрисдикція чи арбітражне застереження. Обидві сторони домовляються при підписанні. У продакшні ML-KEM seed органу зберігається в HSM з політикою ротації ключів.",
  },
  "learn.escrowAuthorityCol": { en: "Escrow authority", uk: "Ескроу-орган" },
  "learn.escrowTriggerCol": { en: "Trigger", uk: "Тригер" },
  "learn.escrowTrustCol": { en: "Trust model", uk: "Модель довіри" },
  "learn.escrowNotary": { en: "Notary", uk: "Нотаріус" },
  "learn.escrowNotaryTrigger": { en: "Court order", uk: "Ухвала суду" },
  "learn.escrowNotaryTrust": { en: "Notary already stores originals", uk: "Нотаріус вже зберігає оригінали" },
  "learn.escrowArbitration": { en: "Arbitration (ICC, LCIA)", uk: "Арбітраж (ICC, LCIA)" },
  "learn.escrowArbitrationTrigger": { en: "Arbitration award", uk: "Арбітражне рішення" },
  "learn.escrowArbitrationTrust": { en: "Standard commercial practice", uk: "Стандартна комерційна практика" },
  "learn.escrowRegistry": { en: "State registry (Diia)", uk: "Держреєстр (Дія)" },
  "learn.escrowRegistryTrigger": { en: "Court order", uk: "Ухвала суду" },
  "learn.escrowRegistryTrust": { en: "Issuer already has the data \u2014 zero new trust", uk: "Видавець вже має дані \u2014 нуль нової довіри" },
  "learn.escrowSmartContract": { en: "Smart contract", uk: "Смарт-контракт" },
  "learn.escrowSmartContractTrigger": { en: "On-chain ruling", uk: "Он-чейн рішення" },
  "learn.escrowSmartContractTrust": { en: "Decentralized fallback", uk: "Децентралізований фолбек" },
  "learn.escrowOverhead": {
    en: "In-circuit encryption adds ~2,500 constraints \u2014 +0.13% over the ~2M base ECDSA constraints. Effectively free.",
    uk: "Шифрування всередині схеми додає ~2,500 обмежень \u2014 +0.13% до ~2M базових обмежень ECDSA. Фактично безкоштовно.",
  },

  // Escrow — Offline vs On-Chain
  "learn.escrowModesTitle": { en: "Offline & On-Chain", uk: "Офлайн та он-чейн" },
  "learn.escrowOfflineTitle": { en: "Offline (Paper Contracts)", uk: "Офлайн (паперові договори)" },
  "learn.escrowOffline1": {
    en: "Proof QR codes printed on paper \u2014 publicly verifiable by any scanner",
    uk: "QR-коди доказів друкуються на папері \u2014 публічно верифіковані будь-яким сканером",
  },
  "learn.escrowOffline2": {
    en: "Escrow QR stored separately by the escrow authority",
    uk: "Ескроу QR зберігається окремо ескроу-органом",
  },
  "learn.escrowOffline3": {
    en: "Court order \u2192 authority decrypts \u2192 reveals identity",
    uk: "Ухвала суду \u2192 орган розшифровує \u2192 розкриває особу",
  },
  "learn.escrowOffline4": {
    en: "The proof and the envelope never travel together",
    uk: "Доказ і конверт ніколи не подорожують разом",
  },
  "learn.escrowOnchainTitle": { en: "On-Chain (Smart Contracts)", uk: "Он-чейн (смарт-контракти)" },
  "learn.escrowOnchain1": {
    en: "Full envelope on-chain \u2014 ciphertext + encrypted key published in the transaction",
    uk: "Повний конверт в ланцюгу \u2014 шифротекст + зашифрований ключ публікуються в транзакції",
  },
  "learn.escrowOnchain2": {
    en: "No dependency on authority storage \u2014 the contract is fully self-contained",
    uk: "Жодної залежності від сховища органу \u2014 контракт повністю самодостатній",
  },
  "learn.escrowOnchain3": {
    en: "Authority needs only their ML-KEM seed to decrypt \u2014 nothing to store",
    uk: "Органу потрібен лише ML-KEM seed для розшифровки \u2014 нічого зберігати",
  },
  "learn.escrowOnchain4": {
    en: "Quantum-safe: ML-KEM-768 (NIST FIPS 203) \u2014 no known quantum attack",
    uk: "Квантово-стійкий: ML-KEM-768 (NIST FIPS 203) \u2014 жодної відомої квантової атаки",
  },

  // Escrow — Quantum Safety
  "learn.escrowQuantumTitle": { en: "Post-Quantum Escrow Envelope", uk: "Постквантовий ескроу-конверт" },
  "learn.escrowQuantumDesc": {
    en: "The escrow envelope is encrypted with ML-KEM-768 (NIST FIPS 203) \u2014 a lattice-based key encapsulation mechanism resistant to quantum attacks. ECIES on secp256k1 would let a future quantum computer decrypt every published contract retroactively. ML-KEM ensures contracts signed today stay sealed against tomorrow\u2019s quantum computers.",
    uk: "Ескроу-конверт зашифрований ML-KEM-768 (NIST FIPS 203) \u2014 решітковий механізм інкапсуляції ключів, стійкий до квантових атак. ECIES на secp256k1 дозволив би майбутньому квантовому комп\u2019ютеру розшифрувати кожен опублікований контракт ретроактивно. ML-KEM гарантує, що контракти підписані сьогодні залишаться запечатаними проти квантових комп\u2019ютерів завтрашнього дня.",
  },

  // Escrow — Architecture
  "learn.escrowArchTitle": { en: "Architecture", uk: "Архітектура" },
  "learn.escrowArchCircuit": { en: "Inside ZK Circuit", uk: "Всередині ZK-схеми" },
  "learn.escrowArchOutside": { en: "Outside Circuit", uk: "Поза схемою" },
  "learn.escrowArchCircuitItems": {
    en: "Commitment chain|ECDSA P-256 binding|Poseidon-CTR encrypt|Poseidon(K) commitment",
    uk: "Ланцюг комітментів|ECDSA P-256 прив\u2019язка|Poseidon-CTR шифрування|Poseidon(K) комітмент",
  },
  "learn.escrowArchOutputs": {
    en: "ciphertexts[]|tags[]|encrypted_key",
    uk: "ciphertexts[]|tags[]|encrypted_key",
  },
  "learn.escrowArchMlkem": { en: "ML-KEM-768 encrypt(K)", uk: "ML-KEM-768 encrypt(K)" },

  // 7b. Proof Attestation
  "learn.attestTitle": { en: "Proof Attestation (QEAA)", uk: "Атестація доказу (QEAA)" },
  "learn.attestSubtitle": {
    en: "A Qualified Trust Service Provider verifies your ZK proof and issues a signed attestation.",
    uk: "Кваліфікований довірений постачальник перевіряє ваш ZK доказ і видає підписану атестацію.",
  },
  "learn.attestWhy": {
    en: "Longfellow proofs are ~350 KB — too large for a QR code. Instead, a qualified TSP verifies the proof and issues a Qualified Electronic Attestation of Attributes (QEAA). The attestation is ~1-2 KB, fits in a single QR code, and is legally meaningful under eIDAS 2.0.",
    uk: "Докази Longfellow мають розмір ~350 КБ — занадто великі для QR-коду. Натомість кваліфікований TSP перевіряє доказ і видає Кваліфіковану Електронну Атестацію Атрибутів (QEAA). Атестація має розмір ~1-2 КБ, поміщається в один QR-код і є юридично значущою за eIDAS 2.0.",
  },
  "learn.attestFlow": {
    en: "Holder proves → TSP verifies → TSP signs attestation → QR code with attestation",
    uk: "Власник доводить → TSP перевіряє → TSP підписує атестацію → QR-код з атестацією",
  },
  "learn.attestOffline": {
    en: "Offline verification works by checking the TSP's signature on the attestation — no need to re-run the ZK proof.",
    uk: "Офлайн верифікація працює через перевірку підпису TSP на атестації — не потрібно повторно запускати ZK доказ.",
  },
  "learn.attestAdvantage": {
    en: "This is actually stronger than raw proof verification: the attestation carries legal weight as a qualified electronic statement under eIDAS 2.0 Article 45d.",
    uk: "Це насправді сильніше за перевірку сирого доказу: атестація має юридичну вагу як кваліфіковане електронне твердження за статтею 45d eIDAS 2.0.",
  },

  // Landing page — quantum callout
  "paperContracts.quantumSafe": {
    en: "Quantum-proof encryption: the identity envelope can't be cracked even by future quantum computers (ML-KEM-768, NIST standard).",
    uk: "Квантовостійке шифрування: конверт особи неможливо зламати навіть майбутніми квантовими комп\u2019ютерами (ML-KEM-768, стандарт NIST).",
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
    en: "Compatible with Architecture Reference Framework v1.4 PID and mDL credential profiles. Conformance tests validate against the exact ARF credential schemas.",
    uk: "Сумісний з Architecture Reference Framework v1.4 профілями PID та mDL. Тести відповідності валідують саме ARF схеми посвідчень.",
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

  // ── Live Proof ─────────────────────────────────────────────────────────
  "liveProof.title": {
    en: "Try it right now",
    uk: "Спробуйте прямо зараз",
  },
  "liveProof.subtitle": {
    en: "Real proof, real verification — running in your browser. Press the button, prove you're 18+, and verify the result. No personal data ever leaves this page.",
    uk: "Справжній доказ, справжня верифікація — прямо у вашому браузері. Натисніть кнопку, доведіть, що вам є 18, і перевірте результат. Жодних персональних даних.",
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
    en: "Contracts without personal data",
    uk: "Контракти без персональних даних",
  },
  "paperContracts.subtitle": {
    en: "Selling a car today means handing your passport data to a stranger. With ZK proofs, the contract proves every condition — age, insurance, ownership — without revealing a single personal detail.",
    uk: "Продаж авто сьогодні означає передачу паспортних даних незнайомцю. З ZK-доказами контракт доводить кожну умову — вік, страховку, власність — не розкриваючи жодної персональної деталі.",
  },
  "paperContracts.todayLabel": {
    en: "Today's paper contract",
    uk: "Сьогоднішній паперовий контракт",
  },
  "paperContracts.todayItems": {
    en: "Your full name, address, birthdate — printed for anyone to see|Passport number shared with a stranger|No way to check if claims are true without calling authorities|Your personal data stored in filing cabinets forever",
    uk: "Ваше ПІБ, адреса, дата народження — надруковані для всіх|Номер паспорта передано незнайомцю|Неможливо перевірити дані без дзвінка в органи|Ваші персональні дані зберігаються у шафах назавжди",
  },
  "paperContracts.zkLabel": {
    en: "With ZK proofs",
    uk: "З ZK-доказами",
  },
  "paperContracts.sellerProved": {
    en: "Seller is 18+, and is the actual vehicle owner",
    uk: "Продавець має 18+, і є фактичним власником ТЗ",
  },
  "paperContracts.vehicleProved": {
    en: "Vehicle is insured, VIN is clean",
    uk: "ТЗ застраховано, VIN чистий",
  },
  "paperContracts.buyerProved": {
    en: "Buyer is 18+",
    uk: "Покупець має 18+",
  },
  "paperContracts.noNames": {
    en: "All proven. No names, no addresses, no birthdates shared.",
    uk: "Все доведено. Жодних імен, адрес чи дат народження.",
  },
  "paperContracts.escrowLine": {
    en: "Identity encrypted inside the proof \u2014 only a trusted authority (notary, court, arbitrator) can unlock it",
    uk: "Особу зашифровано в доказі \u2014 розшифрувати може лише довірений орган (нотаріус, суд, арбітр)",
  },
  "paperContracts.courtResolution": {
    en: "Dispute? Each party's identity is encrypted inside their proof.\nA chosen authority (notary, arbitrator, or court) holds the decryption key.\nOn court order, the authority decrypts \u2014 the claimant learns who the other party is.\nAnonymity is the default. Identification only happens through due process.",
    uk: "Спір? Особу кожної сторони зашифровано в їхньому доказі.\nОбраний орган (нотаріус, арбітр чи суд) тримає ключ розшифровки.\nЗа рішенням суду орган розшифровує \u2014 позивач дізнається, хто інша сторона.\nАнонімність за замовчуванням. Ідентифікація \u2014 лише за процедурою.",
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
    en: "Works across all of Europe",
    uk: "Працює по всій Європі",
  },
  "paperContracts.isolationDesc1": {
    en: "One set of circuits works with every registry in the EU \u2014 civil, vehicle, university, insurance. They don't need to talk to each other. The citizen carries the proof.",
    uk: "Один набір схем працює з кожним реєстром ЄС \u2014 цивільним, транспортним, університетським, страховим. Їм не потрібно спілкуватися між собою. Громадянин несе доказ.",
  },
  "paperContracts.isolationDesc2": {
    en: "27 countries, 27 IT systems, zero integrations needed. A French citizen proves age to a German authority \u2014 France and Germany exchange nothing.",
    uk: "27 країн, 27 ІТ-систем, нуль інтеграцій. Французький громадянин доводить вік німецькому відомству \u2014 Франція і Німеччина не обмінюються нічим.",
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

  // ── Ukraine page ────────────────────────────────────────────────────
  "ua.title": {
    en: "Ukraine & Diia",
    uk: "Україна та Дія",
  },
  "ua.heroSubtitle": {
    en: "The most deployed digital identity app in Europe meets zero-knowledge privacy.",
    uk: "Найпоширеніший застосунок цифрової ідентичності в Європі зустрічає приватність з нульовим розголошенням.",
  },
  "ua.factsTitle": {
    en: "Diia by the numbers",
    uk: "Дія в цифрах",
  },
  "ua.fact1": { en: "24M active users", uk: "24М активних користувачів" },
  "ua.fact2": { en: "Open source, exported to 5+ countries (Estonia, Colombia, Zambia)", uk: "Відкритий код, експортовано в 5+ країн (Естонія, Колумбія, Замбія)" },
  "ua.fact3": { en: "Only non-EU country in the POTENTIAL EUDI Wallet pilot", uk: "Єдина не-ЄС країна в пілоті POTENTIAL EUDI Wallet" },
  "ua.fact4": { en: "Diia.Sign recognized under eIDAS for cross-border signing", uk: "Дія.Підпис визнаний за eIDAS для транскордонного підписання" },
  "ua.fact5": { en: "CMU Resolution #689 — digital ID wallets aligned with eIDAS 2.0", uk: "Постанова КМУ №689 — цифрові ID-гаманці узгоджені з eIDAS 2.0" },
  "ua.fact6": { en: "DT4UA Phase 2 (\u20AC10M from EU, eGA Estonia) — trust services and eID interoperability", uk: "DT4UA Phase 2 (\u20AC10М від ЄС, eGA Естонії) — довірчі сервіси та eID інтероперабельність" },
  "ua.problemTitle": {
    en: "The problem with Diia today",
    uk: "Проблема Дії сьогодні",
  },
  "ua.problem1": { en: "Diia shares full documents (JSON server-to-server)", uk: "Дія шерить повні документи (JSON сервер-до-сервера)" },
  "ua.problem2": { en: "No credentials in the user's hands", uk: "Немає посвідчень у руках юзера" },
  "ua.problem3": { en: "No selective disclosure — a store sees your full passport to verify your age", uk: "Немає вибіркового розкриття — магазин бачить повний паспорт для перевірки віку" },
  "ua.problem4": { en: "Does not comply with eIDAS 2.0 Art. 5a(16) unlinkability requirement", uk: "Не відповідає вимозі незв'язуваності ст. 5a(16) eIDAS 2.0" },
  "ua.solutionTitle": {
    en: "With ZK proofs",
    uk: "З ZK-доказами",
  },
  "ua.solution1": { en: "Diia issues an SD-JWT VC (one change on Diia's side)", uk: "Дія видає SD-JWT VC (одна зміна на стороні Дії)" },
  "ua.solution2": { en: "User generates a ZK proof: \u201CI am 18+\u201D without revealing the passport", uk: "Юзер генерує ZK-доказ: \u00ABмені є 18\u00BB без розкриття паспорта" },
  "ua.solution3": { en: "Offline verification, milliseconds", uk: "Верифікація офлайн, мілісекунди" },
  "ua.solution4": { en: "Unlinkability mathematically guaranteed", uk: "Незв'язуваність математично гарантована" },
  "ua.wartimeTitle": {
    en: "Built in Ukraine during wartime",
    uk: "Розроблено в Україні під час війни",
  },
  "ua.wartime1": { en: "Paper backward compatibility — QR code on A4, works without internet", uk: "Зворотна сумісність з папером — QR-код на А4, працює без інтернету" },
  "ua.wartime2": { en: "Infrastructure resilience — documents work when registries are offline", uk: "Стійкість інфраструктури — документи працюють коли реєстри офлайн" },
  "ua.wartime3": { en: "Proof attestation works offline — QEAA verified by checking the TSP signature", uk: "Атестація доказу працює офлайн — QEAA перевіряється перевіркою підпису TSP" },
  "ua.back": { en: "\u2190 Back", uk: "\u2190 Назад" },
  "nav.ukraine": { en: "Ukraine", uk: "Україна" },

  // ── Learn More nav ───────────────────────────────────────────────────
  "nav.learn": { en: "Learn More", uk: "Дізнатися більше" },

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
  // TODO v2: remove after WASM code cleanup
  "sandbox.generateBrowserBtn": {
    en: "Prove in Browser (snarkjs)",
    uk: "Довести у браузері (snarkjs)",
  },
  // TODO v2: remove after WASM code cleanup
  "sandbox.browserHint": {
    en: "Browser proving requires a lightweight witness endpoint (coming soon). ECDSA signature verification (~2M constraints) runs server-side; only predicate circuits (~300 constraints) can prove in-browser.",
    uk: "Доведення у браузері потребує легковагий ендпоінт для свідка (незабаром). Верифікація підпису ECDSA (~2M обмежень) виконується на сервері; лише предикатні схеми (~300 обмежень) можуть працювати у браузері.",
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
  // TODO v2: remove after WASM code cleanup
  "sandbox.verifyWasm": {
    en: "Verify right here, in your browser",
    uk: "Перевірити прямо тут, у вашому браузері",
  },
  // TODO v2: remove after WASM code cleanup
  "sandbox.wasmUnavailable": { en: "WASM Unavailable", uk: "WASM недоступний" },
  "sandbox.verifyingShort": { en: "Verifying...", uk: "Перевірка..." },
  // TODO v2: remove after WASM code cleanup
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
  // TODO v2: remove after WASM code cleanup
  "sandbox.verifiedWasm": {
    en: "Verified client-side (WASM)",
    uk: "Перевірено на клієнті (WASM)",
  },
  // TODO v2: remove after WASM code cleanup
  "sandbox.verifiedWasmTooltip": {
    en: "Proof verified entirely in your browser using WebAssembly. No data sent to any server.",
    uk: "Доказ перевірено повністю у вашому браузері за допомогою WebAssembly. Дані не відправлено на жоден сервер.",
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
  // TODO v2: remove after WASM code cleanup
  "sandbox.zkProfileToggle": {
    en: "\u25B6 Show WASM execution profile",
    uk: "\u25B6 Показати профіль виконання WASM",
  },
  "sandbox.zkProfileVk": { en: "VK decode", uk: "Декодування VK" },
  "sandbox.zkProfileParse": { en: "Proof parse", uk: "Парсинг доказу" },
  "sandbox.zkProfileInit": { en: "WASM engine", uk: "рушій WASM" },
  "sandbox.zkProfileVerify": { en: "Pairing check", uk: "Перевірка пейрингу" },
  "sandbox.zkProfileTotal": { en: "Total", uk: "Загалом" },
  "sandbox.zkProfileProof": { en: "Proof", uk: "Доказ" },
  "sandbox.zkProfileWasmInit": { en: "WASM initialization (once per page load)", uk: "Ініціалізація WASM (раз за завантаження сторінки)" },
  "sandbox.zkProfileJsImport": { en: "JS module load", uk: "Завантаження JS" },
  "sandbox.zkProfileWasmBoot": { en: "WASM + CRS init", uk: "WASM + CRS ініц." },
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

  // TODO v2: remove entire on-device proving section after WASM code cleanup
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
  "cred.proofSize": { en: "ZK proof: ~800 B compressed", uk: "ZK: ~800 Б стиснений" },
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
  // TODO v2: remove after WASM code cleanup
  "verify.verifyAllWasm": {
    en: "Verify All",
    uk: "Перевірити все",
  },
  // TODO v2: remove after WASM code cleanup
  "verify.initWasm": {
    en: "Initializing...",
    uk: "Ініціалізація...",
  },
  // TODO v2: remove after WASM code cleanup
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
    en: "A proposal for Qualified Trust Service Providers",
    uk: "Пропозиція для кваліфікованих довірених постачальників послуг",
  },
  "proposal.problemTitle": { en: "The Problem", uk: "Проблема" },
  "proposal.problemDesc": {
    en: "Article 5a(16) of Regulation (EU) 2024/1183 mandates that European Digital Identity Wallets enable selective disclosure and unlinkability. Current approaches — SD-JWT with salted hashes and BBS+ batch signatures — offer partial solutions but cannot fully prevent correlation when relying parties collude.",
    uk: "Стаття 5a(16) Регламенту (ЄС) 2024/1183 вимагає, щоб Європейські гаманці цифрової ідентичності забезпечували селективне розкриття та незв'язуваність. Поточні підходи — SD-JWT із солоними хешами та пакетні підписи BBS+ — пропонують часткові рішення, але не можуть повністю запобігти кореляції при змові перевіряючих сторін.",
  },
  "proposal.solutionTitle": { en: "The Solution", uk: "Рішення" },
  "proposal.solutionDesc": {
    en: "zk-eidas uses zero-knowledge proofs to achieve true unlinkability. The holder proves a predicate (e.g., \"age >= 18\") over their mdoc credential without revealing any other data. Each proof is cryptographically unlinkable — even the same holder proving the same predicate to the same verifier produces a different proof each time.",
    uk: "zk-eidas використовує докази з нульовим знанням для досягнення справжньої незв'язуваності. Власник доводить предикат (напр., \"вік >= 18\") над своїм посвідченням mdoc без розкриття інших даних. Кожен доказ криптографічно незв'язуваний — навіть той самий власник, що доводить той самий предикат тому самому верифікатору, генерує різний доказ щоразу.",
  },
  "proposal.provingTitle": { en: "Proving System", uk: "Система доведення" },
  "proposal.provingDesc": {
    en: "Powered by Longfellow (Sumcheck + Ligero), a transparent proving system with no trusted setup. All commitments are hash-based — no pairing-based ceremony. This provides post-quantum security for the proving layer.",
    uk: "Працює на Longfellow (Sumcheck + Ligero) — прозора система доведення без довіреної ініціалізації. Всі зобов'язання базуються на хешах — без церемонії на основі пейрингів. Це забезпечує пост-квантову безпеку для рівня доведення.",
  },
  "proposal.tspTitle": { en: "TSP Service Model", uk: "Модель послуг TSP" },
  "proposal.tspDesc": {
    en: "We propose two services for Qualified Trust Service Providers under eIDAS 2.0:",
    uk: "Ми пропонуємо дві послуги для кваліфікованих довірених постачальників послуг за eIDAS 2.0:",
  },
  "proposal.service1Title": { en: "Service 1: Proof Attestation", uk: "Послуга 1: Атестація доказу" },
  "proposal.service1Desc": {
    en: "The TSP verifies a zero-knowledge proof and issues a Qualified Electronic Attestation of Attributes (QEAA). The attestation is a W3C Verifiable Credential signed with the TSP's qualified certificate. At ~1-2 KB, it fits in a single QR code for offline verification.",
    uk: "TSP перевіряє доказ з нульовим знанням і видає Кваліфіковану Електронну Атестацію Атрибутів (QEAA). Атестація — це W3C Verifiable Credential, підписаний кваліфікованим сертифікатом TSP. Розміром ~1-2 КБ, вона поміщається в один QR-код для офлайн верифікації.",
  },
  "proposal.service1Endpoint": {
    en: "POST /tsp/attest — verify proof, return signed QEAA",
    uk: "POST /tsp/attest — перевірити доказ, повернути підписану QEAA",
  },
  "proposal.service2Title": { en: "Service 2: Identity Escrow Custody", uk: "Послуга 2: Зберігання ескроу ідентичності" },
  "proposal.service2Desc": {
    en: "The TSP holds the private key for identity escrow decryption (ML-KEM-768). Encrypted credential fields are released only on court order or arbitration ruling. This enables accountability while preserving day-to-day privacy.",
    uk: "TSP зберігає приватний ключ для дешифрування ескроу ідентичності (ML-KEM-768). Зашифровані поля посвідчень розкриваються лише за рішенням суду або арбітражу. Це забезпечує підзвітність при збереженні повсякденної приватності.",
  },
  "proposal.service2Endpoint": {
    en: "POST /tsp/escrow/decrypt — decrypt identity fields with court authorization",
    uk: "POST /tsp/escrow/decrypt — дешифрувати поля ідентичності за авторизацією суду",
  },
  "proposal.complianceTitle": { en: "Compliance", uk: "Відповідність" },
  "proposal.complianceItems": {
    en: "eIDAS 2.0 Article 5a(16): unlinkability|eIDAS 2.0 Article 45d: Qualified Electronic Attestation of Attributes|ISO 18013-5: mdoc credential format|Architecture Reference Framework v1.4: PID and mDL profiles|SOG-IS: all primitives approved or NIST standardized|GDPR Article 25: privacy by design",
    uk: "eIDAS 2.0 Стаття 5a(16): незв'язуваність|eIDAS 2.0 Стаття 45d: Кваліфікована Електронна Атестація Атрибутів|ISO 18013-5: формат посвідчень mdoc|Architecture Reference Framework v1.4: профілі PID та mDL|SOG-IS: всі примітиви затверджені або стандартизовані NIST|GDPR Стаття 25: приватність за дизайном",
  },
  "proposal.integrationTitle": { en: "Integration Path", uk: "Шлях інтеграції" },
  "proposal.integrationDesc": {
    en: "An existing Qualified Trust Service Provider can adopt these services with minimal infrastructure. The proving system runs as a single server-side binary. The attestation service requires only an ECDSA P-256 signing key (upgradable to a qualified certificate). The escrow service requires an ML-KEM-768 keypair stored in an HSM.",
    uk: "Існуючий кваліфікований довірений постачальник послуг може впровадити ці послуги з мінімальною інфраструктурою. Система доведення працює як один серверний бінарний файл. Послуга атестації потребує лише ключ підпису ECDSA P-256 (з можливістю оновлення до кваліфікованого сертифіката). Послуга ескроу потребує ключову пару ML-KEM-768, що зберігається в HSM.",
  },
  "proposal.cryptoTitle": { en: "Cryptographic Primitives", uk: "Криптографічні примітиви" },
  "proposal.cryptoItems": {
    en: "Longfellow (Sumcheck + Ligero): transparent ZK proofs, no trusted setup, post-quantum|ECDSA P-256: COSE signature verification, QEAA signing|AES-256-GCM: identity escrow field encryption|ML-KEM-768 (NIST FIPS 203): post-quantum key encapsulation for escrow|SHA-256: content-addressed proof storage (CID)",
    uk: "Longfellow (Sumcheck + Ligero): прозорі ZK докази, без довіреної ініціалізації, пост-квантові|ECDSA P-256: верифікація підписів COSE, підписання QEAA|AES-256-GCM: шифрування полів ескроу ідентичності|ML-KEM-768 (NIST FIPS 203): пост-квантова інкапсуляція ключів для ескроу|SHA-256: контент-адресоване сховище доказів (CID)",
  },
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
