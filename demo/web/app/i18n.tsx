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
    en: "Civil law documents without personal data",
    uk: "Цивільні документи без персональних даних",
  },
  "hero.tagline": {
    en: "Backward compatible with paper.",
    uk: "Зворотна сумісність з папером.",
  },
  "hero.description": {
    en: "An open-source protocol for creating legal documents where every condition is cryptographically proven, zero personal data is exposed, and consent is expressed as a concludent act \u2014 binding a credential to contract terms inside a ZK circuit. Nullifiers enable courts to identify parties through credential issuer subpoena \u2014 and only through judicial process.",
    uk: "Протокол з відкритим кодом для створення юридичних документів де кожна умова криптографічно доведена, жодних персональних даних не розкрито, а згода виражається як конклюдентна дія \u2014 прив\u2019язка посвідчення до умов договору всередині ZK-схеми. Нуліфікатори дозволяють суду ідентифікувати сторони через запит до видавця \u2014 і тільки через судовий процес.",
  },
  "hero.closing": {
    en: "Privacy by default. Accountability by court order.",
    uk: "Приватність за замовчуванням. Відповідальність за судовим рішенням.",
  },
  "hero.tryDemo": { en: "Try the Demo", uk: "Спробувати демо" },
  "hero.viewGithub": { en: "View on GitHub", uk: "Переглянути на GitHub" },

  // ── Learn More page ─────────────────────────────────────────────────────
  "learn.back": { en: "Back", uk: "Назад" },
  "learn.title": { en: "How zk-eidas Works", uk: "Як працює zk-eidas" },
  "learn.subtitle": {
    en: "A technical explainer on zero-knowledge credential verification — from the privacy problem to the proving pipeline, predicates, and standards compliance.",
    uk: "Технічний огляд верифікації посвідчень з нульовим розголошенням — від проблеми приватності до конвеєра доведення, предикатів та відповідності стандартам.",
  },
  "learn.cta": { en: "Try the Playground", uk: "Спробувати пісочницю" },

  // TOC
  "learn.tocProblem": { en: "The Problem", uk: "Проблема" },
  "learn.tocZkp": { en: "ZKP Basics", uk: "Основи ZKP" },
  "learn.tocPipeline": { en: "Pipeline", uk: "Конвеєр" },
  "learn.tocTrustGap": { en: "Trust Gap", uk: "Прогалина довіри" },
  "learn.tocPredicates": { en: "Predicates", uk: "Предикати" },
  "learn.tocAdvanced": { en: "Advanced", uk: "Розширене" },
  "learn.tocStandards": { en: "Standards", uk: "Стандарти" },
  "learn.tocPrivacy": { en: "GDPR", uk: "GDPR" },

  // 1. Problem
  "learn.problemTitle": { en: "The Privacy Problem", uk: "Проблема приватності" },
  "learn.problemSubtitle": {
    en: "Every time you prove your age at a bar, buy age-restricted goods online, or verify your license category — the verifier gets your full credential. Your name, date of birth, address, document number. All of it. For a single yes/no question.",
    uk: "Кожен раз, коли ви підтверджуєте вік у барі, купуєте товари з обмеженням за віком або підтверджуєте категорію прав — верифікатор отримує ваше повне посвідчення. Ваше ім\'я, дату народження, адресу, номер документа. Все. Заради однієї відповіді так/ні.",
  },
  "learn.problemTraditional": { en: "Traditional Verification", uk: "Традиційна верифікація" },
  "learn.problemVerifierSees": { en: "// verifier receives:", uk: "// верифікатор отримує:" },
  "learn.problemTraditionalDesc": {
    en: "The bouncer, the website, the employer — they all see everything. Your credential is fully exposed every time it\'s checked. This data can be stored, leaked, or sold.",
    uk: "Охоронець, вебсайт, роботодавець — всі бачать все. Ваше посвідчення повністю відкрите при кожній перевірці. Ці дані можуть зберігатися, витікати або продаватися.",
  },
  "learn.problemZkTitle": { en: "zk-eidas Verification", uk: "Верифікація zk-eidas" },
  "learn.problemZkDesc": {
    en: "The verifier learns exactly one thing: the predicate holds. The proof is cryptographically bound to the issuer\'s signature — it cannot be forged. But the actual data never leaves the holder\'s device.",
    uk: "Верифікатор дізнається рівно одне: предикат виконується. Доказ криптографічно прив\'язаний до підпису видавця — його неможливо підробити. Але справжні дані ніколи не залишають пристрій власника.",
  },

  // 2. ZKP Basics
  "learn.zkpTitle": { en: "Zero-Knowledge Proofs in 30 Seconds", uk: "Докази з нульовим розголошенням за 30 секунд" },
  "learn.zkpSubtitle": {
    en: "The cryptographic primitive that makes privacy-preserving verification possible.",
    uk: "Криптографічний примітив, який робить можливою верифікацію зі збереженням приватності.",
  },
  "learn.zkpAnalogy1": {
    en: "Imagine you have a color-blind friend and two balls — one red, one green. You want to prove they\'re different colors without telling your friend which is which. You hand them both balls, they hide them behind their back, and either swap them or not. Then they show you the balls and ask: \"Did I swap them?\" You can always tell — because you see the colors. After enough rounds, your friend is convinced the balls are different, but still doesn\'t know which is red and which is green.",
    uk: "Уявіть, що у вас є дальтонік-друг і дві кулі — червона і зелена. Ви хочете довести, що вони різного кольору, не кажучи другу, яка яка. Ви даєте обидві кулі, друг ховає їх за спиною і або міняє місцями, або ні. Потім показує вам кулі і питає: «Я їх поміняв?» Ви завжди можете відповісти — бо бачите кольори. Після достатньої кількості раундів друг переконаний, що кулі різні, але все одно не знає, яка червона, а яка зелена.",
  },
  "learn.zkpAnalogyLabel": { en: "// Applied to credentials:", uk: "// Застосовано до посвідчень:" },
  "learn.zkpAnalogy2": {
    en: "Replace \"balls are different colors\" with \"my birth date is more than 18 years ago.\" The prover (citizen) convinces the verifier (service) that the statement is true, without revealing the actual birth date.",
    uk: "Замініть «кулі різного кольору» на «моя дата народження була більше 18 років тому». Довідник (громадянин) переконує верифікатора (сервіс), що твердження істинне, не розкриваючи фактичну дату народження.",
  },
  "learn.zkpAnalogy3": {
    en: "In zk-eidas, the \"statement\" is a predicate over a signed credential claim, and the \"proof\" is a Groth16 proof generated from a Circom circuit. The two-stage architecture enforces three things: the predicate logic, the claim\'s inclusion in the credential, and the issuer\'s ECDSA signature validity (chained via Poseidon commitment).",
    uk: "У zk-eidas «твердження» — це предикат над підписаним полем посвідчення, а «доказ» — це Groth16 доказ, згенерований з Circom схеми. Двоетапна архітектура забезпечує три речі: логіку предиката, включення поля у посвідчення та дійсність ECDSA підпису видавця (з'єднані через Poseidon комітмент).",
  },
  "learn.zkpCompleteness": { en: "Completeness", uk: "Повнота" },
  "learn.zkpCompletenessDesc": { en: "If the statement is true and both parties follow the protocol, the verifier will always accept.", uk: "Якщо твердження істинне і обидві сторони дотримуються протоколу, верифікатор завжди прийме." },
  "learn.zkpSoundness": { en: "Soundness", uk: "Надійність" },
  "learn.zkpSoundnessDesc": { en: "If the statement is false, no cheating prover can convince the verifier it\'s true (except with negligible probability).", uk: "Якщо твердження хибне, жоден нечесний довідник не зможе переконати верифікатора в його істинності (за виключенням нехтовної ймовірності)." },
  "learn.zkpZeroKnowledge": { en: "Zero Knowledge", uk: "Нуль знань" },
  "learn.zkpZeroKnowledgeDesc": { en: "The verifier learns nothing beyond the truth of the statement. No side-channel information, no metadata leakage.", uk: "Верифікатор не дізнається нічого, крім істинності твердження. Жодної побічної інформації, жодного витоку метаданих." },

  // 3. Pipeline
  "learn.pipelineTitle": { en: "The Proving Pipeline", uk: "Конвеєр доведення" },
  "learn.pipelineSubtitle": {
    en: "From raw credential to opaque proof bytes — here\'s exactly what happens when a citizen proves a predicate.",
    uk: "Від сирого посвідчення до непрозорих байтів доказу — ось що саме відбувається, коли громадянин доводить предикат.",
  },
  "learn.pipelineCredential": { en: "Credential", uk: "Посвідчення" },
  "learn.pipelineParser": { en: "Parser", uk: "Парсер" },
  "learn.pipelineParserSub": { en: "Claims + Key", uk: "Поля + Ключ" },
  "learn.pipelineWitness": { en: "Witness", uk: "Свідок" },
  "learn.pipelineWitnessSub": { en: "Field Elements", uk: "Елементи поля" },
  "learn.pipelineCircuit": { en: "Circom Circuit", uk: "Circom схема" },
  "learn.pipelineCircuitSub": { en: "ECDSA + Predicate", uk: "ECDSA + Предикат" },
  "learn.pipelineProof": { en: "ZK Proof", uk: "ZK Доказ" },
  "learn.pipelineProofSub": { en: "Opaque Bytes", uk: "Непрозорі байти" },
  "learn.pipelineVerifier": { en: "Verifier", uk: "Верифікатор" },
  "learn.pipelineVerifierSub": { en: "Pass / Fail", uk: "Так / Ні" },
  "learn.step1Title": { en: "Parse the Credential", uk: "Розбір посвідчення" },
  "learn.step1Desc": {
    en: "The SD-JWT VC (or mdoc) is parsed into individual claims. Each claim is a key-value pair with a salt and a disclosure hash. The parser also extracts the issuer\'s ECDSA P-256 public key from the JWT header.",
    uk: "SD-JWT VC (або mdoc) розбирається на окремі поля. Кожне поле — це пара ключ-значення з сіллю та хешем розкриття. Парсер також витягує публічний ключ ECDSA P-256 видавця з заголовка JWT.",
  },
  "learn.step1Detail": {
    en: "SD-JWT format: header.payload~disclosure1~disclosure2~...  Each disclosure is base64url(json([salt, key, value])). The SHA-256 hash of each disclosure is embedded in the signed payload.",
    uk: "Формат SD-JWT: header.payload~disclosure1~disclosure2~...  Кожне розкриття — base64url(json([salt, key, value])). SHA-256 хеш кожного розкриття вбудований у підписаний payload.",
  },
  "learn.step2Title": { en: "Build the Witness", uk: "Побудова свідка" },
  "learn.step2Desc": {
    en: "The claim value is converted to field elements — the native number type of the ZK circuit. Dates become epoch-day integers, strings become SHA-256 hashes, booleans become 0/1. The witness includes the claim value, the disclosure salt, the signature components (r, s), and the public key coordinates.",
    uk: "Значення поля конвертується в елементи поля — нативний числовий тип ZK схеми. Дати стають цілими числами epoch-day, рядки — SHA-256 хешами, булеві — 0/1. Свідок включає значення поля, сіль розкриття, компоненти підпису (r, s) та координати публічного ключа.",
  },
  "learn.step2Detail": { en: "All witness inputs are private — the circuit never exposes them. The only public inputs are the predicate parameters (e.g., threshold=18) and the verification result.", uk: "Всі входи свідка приватні — схема ніколи їх не розкриває. Єдині публічні входи — параметри предиката (напр., поріг=18) та результат верифікації." },
  "learn.step3Title": { en: "Execute the Circom Circuit", uk: "Виконання Circom схеми" },
  "learn.step3Desc": {
    en: "The circuit does three things in one execution: (1) verifies the issuer\'s ECDSA P-256 signature over the JWT payload, (2) checks that the SHA-256 hash of the disclosure matches what\'s in the signed payload, and (3) evaluates the predicate (e.g., age >= 18). If any check fails, proof generation fails.",
    uk: "Схема робить три речі за одне виконання: (1) перевіряє ECDSA P-256 підпис видавця над JWT payload, (2) перевіряє, що SHA-256 хеш розкриття збігається з тим, що в підписаному payload, та (3) обчислює предикат (напр., вік >= 18). Якщо будь-яка перевірка не пройде, генерація доказу провалюється.",
  },
  "learn.step4Title": { en: "Generate the Groth16 Proof", uk: "Генерація Groth16 доказу" },
  "learn.step4Desc": {
    en: "The Groth16 prover (ark-circom on server, snarkjs in browser) takes the satisfied circuit and produces a compact proof. Groth16 uses per-circuit trusted setup (.zkey files). The proof is an opaque byte sequence that encodes the execution trace without revealing any witness values.",
    uk: "Groth16 доводчик (ark-circom на сервері, snarkjs у браузері) бере задоволену схему і створює компактний доказ. Groth16 використовує довірену ініціалізацію для кожної схеми (.zkey файли). Доказ — непрозора послідовність байтів, яка кодує трасу виконання без розкриття значень свідка.",
  },
  "learn.step4Detail": { en: "Proving takes ~1-3 seconds on server hardware. The proof size is constant regardless of credential complexity.", uk: "Доведення займає ~1-3 секунди на серверному обладнанні. Розмір доказу постійний незалежно від складності посвідчення." },
  "learn.step5Title": { en: "Verify", uk: "Верифікація" },
  "learn.step5Desc": {
    en: "The verifier derives the verification key from the circuit bytecode — never trusting prover-supplied keys. Verification checks the proof against the public inputs (predicate parameters). It runs in ~5ms on a server or <100ms in a browser via WASM.",
    uk: "Верифікатор виводить ключ верифікації з байткоду схеми — ніколи не довіряючи ключам від довідника. Верифікація перевіряє доказ проти публічних входів (параметрів предиката). Вона виконується за ~5мс на сервері або <100мс у браузері через WASM.",
  },
  "learn.step5Detail": { en: "Browser verification uses snarkjs — the same Groth16 verifier running in JavaScript. No server round-trip needed.", uk: "Верифікація в браузері використовує snarkjs — той самий Groth16 верифікатор, що працює на JavaScript. Без серверних запитів." },

  // 4. Trust Gap
  "learn.trustGapTitle": { en: "The Trust Gap", uk: "Прогалина довіри" },
  "learn.trustGapSubtitle": {
    en: "Most ZK credential systems have a critical weakness: they verify the signature outside the circuit. This means the prover can fabricate claims and the verifier has no way to know.",
    uk: "Більшість ZK систем для посвідчень мають критичну слабкість: вони перевіряють підпис поза схемою. Це означає, що довідник може сфабрикувати дані, і верифікатор не зможе це виявити.",
  },
  "learn.trustGapTypical": { en: "Typical ZK Approach", uk: "Типовий ZK підхід" },
  "learn.trustGapTyp1": { en: "Step 1: Verify the issuer\'s signature externally (outside the circuit).", uk: "Крок 1: Перевірити підпис видавця зовні (поза схемою)." },
  "learn.trustGapTyp2": { en: "Step 2: Prove the predicate inside the circuit over self-supplied data.", uk: "Крок 2: Довести предикат всередині схеми над самостійно наданими даними." },
  "learn.trustGapTypCode": { en: "// Nothing binds step 1 to step 2 — the prover\n// could pass fabricated claims to the circuit", uk: "// Ніщо не зв\'язує крок 1 з кроком 2 — довідник\n// може передати сфабриковані дані в схему" },
  "learn.trustGapZk1": {
    en: "Everything happens inside a single circuit: ECDSA signature verification, disclosure hash binding, and predicate evaluation.",
    uk: "Все відбувається всередині однієї схеми: перевірка підпису ECDSA, прив\'язка хешу розкриття та обчислення предиката.",
  },
  "learn.trustGapZk2": {
    en: "The prover cannot fabricate claims because the circuit independently verifies the issuer\'s signature over the exact data used in the predicate.",
    uk: "Довідник не може сфабрикувати дані, тому що схема незалежно перевіряє підпис видавця над саме тими даними, що використовуються в предикаті.",
  },
  "learn.trustGapZkCode": { en: "// One proof covers the full chain:\n// issuer → signature → claim → predicate\n// No trust gap. No fabrication possible.", uk: "// Один доказ покриває весь ланцюг:\n// видавець → підпис → поле → предикат\n// Без прогалини довіри. Фабрикація неможлива." },

  // 5. Predicates
  "learn.predicatesTitle": { en: "Predicates", uk: "Предикати" },
  "learn.predicatesSubtitle": {
    en: "A predicate is a boolean function over a credential claim. Each predicate type has a dedicated Circom circuit with ECDSA signature verification built in.",
    uk: "Предикат — це булева функція над полем посвідчення. Кожен тип предиката має окрему Circom схему з вбудованою перевіркою підпису ECDSA.",
  },
  "learn.predType": { en: "Type", uk: "Тип" },
  "learn.predDescription": { en: "Description", uk: "Опис" },
  "learn.predExample": { en: "Example", uk: "Приклад" },
  "learn.predGteDesc": { en: "Greater than or equal — numeric comparison", uk: "Більше або дорівнює — числове порівняння" },
  "learn.predLteDesc": { en: "Less than or equal — numeric comparison", uk: "Менше або дорівнює — числове порівняння" },
  "learn.predEqDesc": { en: "Equality — hash-based comparison for strings", uk: "Рівність — порівняння на основі хешу для рядків" },
  "learn.predNeqDesc": { en: "Not equal — proves value differs from a target", uk: "Не дорівнює — доводить, що значення відрізняється від цільового" },
  "learn.predRangeDesc": { en: "Range check — value within bounds", uk: "Перевірка діапазону — значення в межах" },
  "learn.predSetDesc": { en: "Set membership — value is one of up to 16 allowed values", uk: "Членство у множині — значення є одним з до 16 допустимих" },
  "learn.predNullDesc": { en: "Scoped replay prevention — deterministic, unlinkable across scopes", uk: "Скопована протидія повторному використанню — детерміновано, без зв\'язку між скопами" },
  "learn.predicatesNote": { en: "Every predicate circuit includes full ECDSA P-256 signature verification. There are no unsigned circuit variants — all proofs are cryptographically bound to authentic credentials.", uk: "Кожна схема предиката включає повну перевірку підпису ECDSA P-256. Непідписаних варіантів схем не існує — всі докази криптографічно прив\'язані до автентичних посвідчень." },

  // 6. Advanced
  "learn.advancedTitle": { en: "Advanced Features", uk: "Розширені можливості" },
  "learn.advancedSubtitle": { en: "Beyond single predicates — compound logic, replay prevention, revocation, and cross-credential binding.", uk: "За межами окремих предикатів — складена логіка, протидія повторному використанню, відкликання та міждокументна прив\'язка." },
  "learn.advCompoundTitle": { en: "Compound Predicates (AND / OR)", uk: "Складені предикати (AND / OR)" },
  "learn.advCompoundDesc": { en: "Combine multiple predicates with boolean logic. AND requires all sub-proofs to verify. OR requires at least one. Each sub-proof independently verifies its own ECDSA signature.", uk: "Поєднуйте кілька предикатів за допомогою булевої логіки. AND вимагає верифікації всіх під-доказів. OR — принаймні одного. Кожен під-доказ незалежно перевіряє свій ECDSA підпис." },
  "learn.advNullifierTitle": { en: "Scoped Nullifiers", uk: "Скоповані нуліфікатори" },
  "learn.advNullifierDesc": {
    en: "A nullifier is a deterministic, scope-specific token derived from the holder\'s secret and the verifier\'s scope string. The same credential produces different nullifiers for different services, making cross-service linking impossible.",
    uk: "Нуліфікатор — це детермінований, специфічний для скопу токен, отриманий з секрету власника та рядка скопу верифікатора. Одне посвідчення створює різні нуліфікатори для різних сервісів, що унеможливлює міжсервісне зв\'язування.",
  },
  "learn.advRevocationTitle": { en: "Credential Revocation", uk: "Відкликання посвідчень" },
  "learn.advRevocationDesc": {
    en: "Uses a Sparse Merkle Tree (SMT) to prove a credential has NOT been revoked. The issuer publishes the tree root; the holder generates a non-membership proof inside the circuit.",
    uk: "Використовує розріджене дерево Меркла (SMT) для доведення того, що посвідчення НЕ було відкликано. Видавець публікує корінь дерева; власник генерує доказ невключення всередині схеми.",
  },
  "learn.advBindingTitle": { en: "Holder Binding", uk: "Прив\'язка власника" },
  "learn.advBindingDesc": {
    en: "Proves that two different credentials (e.g., a national ID and a driver\'s license) belong to the same person, without revealing the shared identifier. Uses SHA-256 commitments compared inside the circuit.",
    uk: "Доводить, що два різних посвідчення (напр., національний ID та водійські права) належать одній особі, не розкриваючи спільний ідентифікатор. Використовує SHA-256 commitments, порівнювані всередині схеми.",
  },

  // 7. Standards
  "learn.standardsTitle": { en: "Standards Compliance", uk: "Відповідність стандартам" },
  "learn.standardsSubtitle": { en: "Built natively for eIDAS 2.0 — not retrofitted. Every supported standard is tested against the spec.", uk: "Розроблено нативно для eIDAS 2.0 — не адаптовано. Кожен підтримуваний стандарт перевірений проти специфікації." },
  "learn.stdEidas": { en: "The EU Digital Identity Framework mandating digital wallets for all EU citizens by 2026. zk-eidas supports the PID credential profile specified in the Architecture Reference Framework.", uk: "Рамка цифрової ідентичності ЄС, що зобов\'язує до цифрових гаманців для всіх громадян ЄС до 2026. zk-eidas підтримує профіль PID, визначений у Architecture Reference Framework." },
  "learn.stdSdjwt": { en: "Selective Disclosure JSON Web Tokens (RFC 9901) — the primary credential format for EUDI Wallets. Each claim is individually disclosable via salted SHA-256 hashes.", uk: "Selective Disclosure JSON Web Tokens (RFC 9901) — основний формат посвідчень для EUDI Wallets. Кожне поле може розкриватися окремо через SHA-256 хеші з сіллю." },
  "learn.stdMdoc": { en: "ISO 18013-5 mobile document format with COSE_Sign1 signatures. Used for mobile driver\'s licenses (mDL). zk-eidas verifies COSE_Sign1 signatures inside the same ZK circuits.", uk: "Формат мобільних документів ISO 18013-5 з підписами COSE_Sign1. Використовується для мобільних водійських посвідчень (mDL). zk-eidas перевіряє підписи COSE_Sign1 всередині тих самих ZK схем." },
  "learn.stdEcdsa": { en: "The signature algorithm specified by both SD-JWT VC (ES256) and mdoc (COSE_Sign1). P-256 curve, verified inside the Circom circuit for every proof.", uk: "Алгоритм підпису, визначений як для SD-JWT VC (ES256), так і для mdoc (COSE_Sign1). Крива P-256, перевіряється всередині Circom схеми для кожного доказу." },
  "learn.stdOpenid": { en: "OpenID for Verifiable Presentations — the transport protocol for requesting and receiving ZK proofs from EUDI Wallets. zk-eidas generates PresentationDefinition and InputDescriptor objects.", uk: "OpenID for Verifiable Presentations — транспортний протокол для запиту та отримання ZK доказів від EUDI Wallets. zk-eidas генерує PresentationDefinition та InputDescriptor об\'єкти." },
  "learn.stdEudi": { en: "The EUDI Wallet Architecture Reference Framework defines the PID credential schema (birth_date, age_over_18, issuing_country, etc.). zk-eidas conformance tests validate against this exact schema.", uk: "EUDI Wallet Architecture Reference Framework визначає схему PID посвідчення (birth_date, age_over_18, issuing_country тощо). Тести відповідності zk-eidas валідують саме цю схему." },

  // 8. Privacy
  "learn.privacyTitle": { en: "GDPR: Privacy by Design", uk: "GDPR: Приватність за дизайном" },
  "learn.privacyDesc": {
    en: "zk-eidas implements GDPR\'s data minimization principle at the cryptographic level. Zero-knowledge proofs reveal only boolean predicate results — never raw personal data. Scoped nullifiers prevent cross-context tracking. No personal data is stored, processed, or transmitted by the library.",
    uk: "zk-eidas реалізує принцип мінімізації даних GDPR на криптографічному рівні. Докази з нульовим розголошенням розкривають лише булеві результати предикатів — ніколи сирі персональні дані. Скоповані нуліфікатори запобігають міжконтекстному відстеженню. Бібліотека не зберігає, не обробляє та не передає жодних персональних даних.",
  },
  "learn.privacyMinimization": { en: "Data Minimization", uk: "Мінімізація даних" },
  "learn.privacyMinimizationDesc": { en: "Proofs reveal only boolean results. No raw claim values ever leave the holder.", uk: "Докази розкривають лише булеві результати. Жодне сире значення не залишає власника." },
  "learn.privacyLimitation": { en: "Purpose Limitation", uk: "Обмеження цілей" },
  "learn.privacyLimitationDesc": { en: "Each proof is scoped to a specific predicate. A verifier can\'t repurpose it for other checks.", uk: "Кожен доказ прив\'язаний до конкретного предиката. Верифікатор не може використати його для інших перевірок." },
  "learn.privacyStorage": { en: "Zero Storage", uk: "Нуль зберігання" },
  "learn.privacyStorageDesc": { en: "The library stores no personal data. Proofs are transient. Nothing to breach.", uk: "Бібліотека не зберігає персональних даних. Докази тимчасові. Нічого для витоку." },

  // ── Capabilities ─────────────────────────────────────────────────────────
  "caps.title": {
    en: "Beyond Verification \u2014 A New Type of Document",
    uk: "Більше ніж верифікація \u2014 новий тип документу",
  },
  "caps.subtitle": {
    en: "Zero-knowledge proofs are just the start. Verify in the browser, print on paper, generate legally-styled documents — all without a server.",
    uk: "Докази з нульовим розголошенням — лише початок. Перевіряйте у браузері, друкуйте на папері, створюйте юридичні документи — без сервера.",
  },
  "caps.wasmTitle": {
    en: "Consent as Concludent Act",
    uk: "Згода як конклюдентна дія",
  },
  "caps.wasmDesc": {
    en: "Binding a credential to the contract hash inside a ZK circuit. Impossible to forge, impossible to deny, bound to specific terms. Stronger than a signature.",
    uk: "Прив\u2019язка посвідчення до хешу контракту всередині ZK-схеми. Неможливо підробити, неможливо заперечити, прив\u2019язано до конкретних умов. Сильніше за підпис.",
  },
  "caps.wasmCta": {
    en: "Try it in the playground",
    uk: "Спробувати у пісочниці",
  },
  "caps.paperTitle": {
    en: "Backward Compatibility with Paper",
    uk: "Зворотна сумісність з папером",
  },
  "caps.paperDesc": {
    en: "Any digital credential can be issued on paper and verified offline. ZK proofs embed as chunked QR codes on standard A4 — verifiable with any camera, no app or internet needed.",
    uk: "Будь-який цифровий документ можна видати на папері та перевірити офлайн. ZK-докази вбудовуються як QR-коди на стандартному A4 — перевіряються будь-якою камерою, без застосунку чи інтернету.",
  },
  "caps.paperCta": {
    en: "Try offline verification",
    uk: "Спробувати офлайн-перевірку",
  },
  "caps.contractsTitle": {
    en: "Dispute Resolution Through Court",
    uk: "Вирішення спорів через суд",
  },
  "caps.contractsDesc": {
    en: "Nullifiers are unique per contract, unlinkable across documents. A court subpoenas the credential issuer \u2014 and only the issuer can identify the party. Privacy by default, accountability by court order.",
    uk: "Нуліфікатори \u2014 унікальні для кожного контракту, незв\u2019язувані між документами. Суд запитує видавця посвідчень \u2014 і тільки видавець може ідентифікувати сторону. Приватність за замовчуванням, відповідальність за судовим рішенням.",
  },
  "caps.contractsCta": {
    en: "Try the demo",
    uk: "Спробувати демо",
  },

  // ── Live Proof ─────────────────────────────────────────────────────────
  "liveProof.title": {
    en: "Try It Yourself",
    uk: "Спробуйте самі",
  },
  "liveProof.subtitle": {
    en: "Generate a real ZK proof on our server, then verify it entirely in your browser. No trust required.",
    uk: "Згенеруйте справжній ZK-доказ на нашому сервері, а потім перевірте його повністю у вашому браузері. Довіра не потрібна.",
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
    en: "Bureaucracy 2.0: Contracts Without Personal Data",
    uk: "Бюрократія 2.0: контракт без персональних даних",
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
  "footer.research": {
    en: 'A research project at the intersection of cryptography and civil law.\nExtending the "verification dilemmas" framework (Bamberger, Goldwasser, Wexler, 2022) to persistent legal documents.\n\nBuilt in Ukraine during wartime. That\u2019s why \u2014 backward compatible with paper.',
    uk: "Дослідницький проект на перетині криптографії та цивільного права.\nРозширює рамку \u201Cverification dilemmas\u201D (Bamberger, Goldwasser, Wexler, 2022) на персистентні юридичні документи.\n\nРозроблено в Україні під час війни. Тому \u2014 сумісність з папером.",
  },
  "footer.license": {
    en: "Apache 2.0 License \u00B7 Open Source",
    uk: "Ліцензія Apache 2.0 \u00B7 Відкритий код",
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
