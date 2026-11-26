# منشئ حسابات Gmail — دليل عربي مفصّل

[![English README](https://img.shields.io/badge/README-English-blue)](README.md)
[![المستودع على GitHub](https://img.shields.io/badge/GitHub-code--root%2Fgmail--account--creator-181717?logo=github)](https://github.com/code-root/gmail-account-creator)
[![Releases](https://img.shields.io/github/v/release/code-root/gmail-account-creator?label=Releases&logo=github)](https://github.com/code-root/gmail-account-creator/releases)
[![Packages](https://img.shields.io/badge/Packages-npm-24292f?logo=github)](https://github.com/code-root/gmail-account-creator/pkgs/npm/gmail-account-creator)

## فهرس المحتويات

**انتقال سريع:** [English README (`README.md`)](README.md#table-of-contents) · [المستودع على GitHub](https://github.com/code-root/gmail-account-creator)

| القسم | |
|--------|---|
| [حول المشروع (About)](#حول-المشروع-about) | [وصف المشروع (تفصيل تقني)](#وصف-المشروع-تفصيل-تقني) |
| [المتطلبات قبل البدء](#المتطلبات-قبل-البدء) | [التثبيت — خطوة بخطوة](#التثبيت--خطوة-بخطوة) |
| [التشغيل — أوامر وشرح السلوك](#التشغيل--أوامر-وشرح-السلوك) | [ماذا يحدث داخل البرنامج؟](#ماذا-يحدث-داخل-البرنامج-تسلسل-العمليات) |
| [مخططات توضيحية](#مخططات-توضيحية) | [جدول الوحدات البرمجية](#جدول-الوحدات-البرمجية-ملف--مسؤولية) |
| [مرجع الدوال](#مرجع-الدوال-شرح-مختصر-لكل-دالة-مصدَّرة-أو-método-عام) | [المخرجات والسجلات](#المخرجات-والسجلات) |
| [الإصدارات و GitHub Packages](#الإصدارات-releases-وحزمة-github-packages) | [سير عمل GitHub المقترح](#سير-عمل-github-المقترح-حسب-التقنية) |
| [المطوّر والشركة والتواصل](#المطوّر-والشركة-والتواصل) | [دعم المشروع](#دعم-المشروع-support) |
| [تحذير قانوني وأخلاقي](#تحذير-قانوني-وأخلاقي) | [مراجع سريعة داخل المستودع](#مراجع-سريعة-داخل-المستودع) |

**المخططات (داخل القسم)**

- [السياق العام للنظام](#السياق-العام-للنظام)
- [تسلسل محاولة واحدة حتى التسليم](#تسلسل-محاولة-واحدة-حتى-التسليم)
- [مسار التسجيل داخل Gmail (منطقي)](#مسار-التسجيل-داخل-gmail-منطقي)
- [جدول — نموذج التزامن](#جدول--نموذج-التزامن)

**الإصدارات والحزم (أقسام فرعية)**

- [الخيار أ — إصدار تلقائي (مُستحسن)](#الخيار-أ--إصدار-تلقائي-مُستحسن)
- [الخيار ب — من واجهة GitHub: «Create a new release»](#الخيار-ب--من-واجهة-github-create-a-new-release)
- [التثبيت من GitHub Packages](#التثبيت-من-github-packages)
- [النشر التلقائي](#النشر-التلقائي)

**الدعم**

- [رموز QR للإيداع (امسح ضوئياً في Binance أو أي محفظة BSC)](#رموز-qr-للإيداع-امسح-ضوئياً-في-binance-أو-أي-محفظة-bsc)

---

## حول المشروع (About)

**منشئ حسابات Gmail** أداة **Node.js** تفتح مسار إنشاء حساب Google في بروفايل متصفح وتسجّل نتيجة المحاولة. تعالج الواجهة الحقول الأولية التي يمكن التحقق منها وتسلّم إدخال كلمة المرور والتحقق والموافقة وتأكيد الحساب إلى صاحبه. تُسجّل حالة `MANUAL_SIGNUP_REQUIRED` عند التسليم ويحاول التطبيق إيقاف البروفايل المُدار. أكمل الخطوات المتبقية وتحقق من هوية الحساب في متصفح موثوق.

| | |
|--|--|
| **المستودع** | [github.com/code-root/gmail-account-creator](https://github.com/code-root/gmail-account-creator) |
| **Releases** | [تبويب الإصدارات](https://github.com/code-root/gmail-account-creator/releases) — **Create a new release** من الواجهة، أو دفع وسم `v*` لإرفاق `.tgz` تلقائياً |
| **Packages** | [حزم npm على GitHub](https://github.com/code-root/gmail-account-creator/pkgs/npm/gmail-account-creator) — `@code-root/gmail-account-creator` |
| **المسؤول عن الصيانة** | مصطفى البغوري — [Storage TE](http://storage-te.com/) — [واتساب](https://wa.me/201001995914) |
| **الترخيص** | ISC — راجع [`LICENSE`](LICENSE) |

**الوصف القصير (Description) على GitHub (إنجليزي):**  
*Automated Gmail signup (Node.js ESM): GPM Login / Dolphin Anty antidetect, Puppeteer, OMO Captcha & SMS APIs. Proxies and human-like behavior to reduce blocks, restrictions, and ban risk.*

**بالعربية (معنى الوصف):** أتمتة إنشاء حسابات Gmail مع بروفايلات مضادة للبصمة وسلوك شبيه بالإنسان وبروكسيات — بهدف **تقليل الحظر والقيود وتقليل احتمال تقييد الحساب** (لا يوجد ضمان مطلق؛ يلتزم المستخدم بشروط الخدمات).

**الوسوم (Topics / Tags) على GitHub (حد أقصى 20):**  
`gmail` · `gmail-creator` · `automation` · `account-creation` · `puppeteer` · `nodejs` · `javascript` · `gpm-login` · `dolphin-anty` · `antidetect-browser` · `anti-ban` · `ban-avoidance` · `undetected-automation` · `captcha` · `recaptcha` · `sms-verification` · `browser-automation` · `dotenv` · `axios` · `github-packages`

---

هذا المستند يشرح **الخطوات والعمليات** بالتفصيل، ويتضمن **مخططات Mermaid**، **جداول للوحدات**، و**مرجعاً للدوال**. النسخة الإنجليزية في [`README.md`](README.md).

---

## وصف المشروع (تفصيل تقني)

التطبيق يشغّل **متصفحاً حقيقياً** داخل **بروفايل مضاد للبصمة** عبر:

- **GPM Login** (الافتراضي)، أو  
- **Dolphin Anty**

ثم يستخدم **Puppeteer** للاتصال بالمتصفح ومعالجة الخطوات الأولية المدعومة. يراجع صاحب الحساب طلبات التحقق والموافقة بنفسه. مكتبة **SMS Verification** منفصلة عن مسار التسجيل وتستخدم مفتاحها الخاص.

---

## المتطلبات قبل البدء

1. **Node.js 18 أو أحدث** (مستحسن).  
2. **GPM Login** أو **Dolphin Anty** أو محرك **Camoufox** مثبّت محلياً. اضبط عنوان HTTPS الموثوق لوحدة التحكم أو اسمح صراحة بعنوان HTTP الرقمي المحلي المطابق على مضيف موثوق. راجع [إعداد الاتصال](ENV_VARIABLES.md#browser-controller-connection).
3. ملف `config/proxies.txt` بصيغة صحيحة في مجلد الحالة عندما يتطلب وضع البروفايل بروكسي.
4. ملف `config/names.json` المُرفق بالمشروع لتوليد بيانات الحساب.

---

## التثبيت — خطوة بخطوة

### 1) استنساخ المشروع وتثبيت الحزم

```bash
git clone https://github.com/code-root/gmail-account-creator.git
cd gmail-account-creator
npm install
```

**ماذا يحدث؟** يتم تنزيل الاعتماديات من `package.json`، أهمها: `puppeteer-core`, `axios`, `dotenv`, `gologin`.

### 2) إنشاء ملفات الإعدادات الخاصة

على أنظمة POSIX، أنشئ مجلد الحالة والملفات التالية بحساب تشغيل التطبيق قبل إضافة المفاتيح وبيانات اعتماد البروكسي.

```bash
export GMAIL_CREATOR_STATE_DIR="$HOME/.local/state/gmail-account-creator"
(
  umask 077
  mkdir -p "$GMAIL_CREATOR_STATE_DIR/config" &&
    set -C &&
    cat .env.example > "$GMAIL_CREATOR_STATE_DIR/.env" &&
    : > "$GMAIL_CREATOR_STATE_DIR/config/proxies.txt"
)
```

امنح المالك وحده صلاحية الوصول إلى الملفات العادية الموجودة بتعيين الوضع `0600` لكل من `.env` و`.emv` الاختياري و`config/proxies.txt` قبل تحريرها. على Windows، اضبط قائمة التحكم بالوصول لمجلد الحالة على NTFS وتحقق من أن صلاحيات الملفات الموجودة والجديدة تقتصر على حساب التشغيل وحسابات النظام المصرح لها.

**أهم المتغيرات:**

| المتغير | الوظيفة |
|---------|---------|
| `PROFILE_SERVICE` | `gpm` (افتراضي) أو `dolphin` أو `camoufox` لاختيار منصة البروفايلات |
| `GMAIL_CREATOR_STATE_DIR`, `GMAIL_CREATOR_LEGACY_DIR` | مسارات مطلقة لمجلدي الحالة والتهيئة السابقة، تُضبط في بيئة التشغيل |
| `GPM_API_URL` | عنوان API لـ GPM Login |
| `DOLPHIN_API_KEY`, `DOLPHIN_API_URL`, `DOLPHIN_FOLDER_ID` | إعدادات Dolphin عند اختيار `dolphin` |
| `GPM_TRUSTED_HTTP_API_URL`, `DOLPHIN_TRUSTED_HTTP_API_URL` | الموافقة الصريحة على عنوان HTTP الرقمي المحلي المطابق |
| `SMS_VERIFY_API_KEY` | مفتاح اختياري لاستخدام مكتبة SMS Verification بصورة مستقلة |
| `SMS_PROVIDER` | `sms-verification` — التفاصيل في [`ENV_VARIABLES.md`](ENV_VARIABLES.md) |
| `ACCOUNTS_COUNT` | عدد الحسابات المطلوب إنشاؤها في التشغيلة |
| `THREADS_COUNT` | عدد المهام المتزامنة (الخيوط) |

**ملاحظة:** الكود يحمّل `.env` أولاً، ويمكنه تجربة ملف `.emv` في حالات معيّنة إذا لم تُضبط متغيرات معيّنة — راجع `src/config.js`.

### 3) إعداد البروكسيات

الملف هو `config/proxies.txt` داخل مجلد الحالة.

- سطر لكل بروكسي.  
- الصيغة: `ip:port` أو `ip:port:username:password`  
- الأسطر التي تبدأ بـ `#` تُعتبر تعليقاً.

يتوقف التشغيل إذا كان أي سطر من غير التعليقات غير صالح.

### 4) إعداد الأسماء

الملف: `config/names.json` — يُستخدم لتوليد أسماء ومقترحات بريد منطقية ضمن `src/utils/name-generator.js`.

---

## التشغيل — أوامر وشرح السلوك

### تشغيل افتراضي (حساب واحد، خيط واحد)

```bash
npm start
```

### تشغيل دفعات مع تزامن

```bash
npm start -- --accounts=10 --threads=3
npm start -- -a=10 -t=3
```

أو:

```bash
ACCOUNTS_COUNT=10 THREADS_COUNT=3 npm start
```

**شرح المعاملات:**

- `--accounts` / `ACCOUNTS_COUNT`: كم **محاولة إنشاء** سيتم جدولتها.  
- `--threads` / `THREADS_COUNT`: كم **عملية متزامنة** تعمل في نفس الوقت. إذا كان عدد الخيوط أكبر من عدد الحسابات، يُعدّل البرنامج الخيوط لتطابق عدد الحسابات (راجع `src/index.js`).

### وضع التطوير (إعادة تشغيل عند التغيير)

```bash
npm run dev
```

يستخدم `node --watch` لملف الدخول.

### سكربت مجلدات Dolphin

```bash
npm run list-folders
```

مفيد عند ضبط `DOLPHIN_FOLDER_ID`.

---

## ماذا يحدث داخل البرنامج؟ (تسلسل العمليات)

يُنفَّذ المنطق الرئيسي في `src/index.js` بالترتيب التالي **لكل محاولة حساب**:

1. **اختيار بروكسي** من `proxy-manager` حسب الدور أو السياسة المعرفة في الكود.  
2. **توليد بيانات الحساب** (اسم، اسم مستخدم، إلخ) عبر `name-generator`.  
3. **إنشاء بروفايل** باسم يتضمن بادئة `Gmail_` والوقت، ثم **تشغيله** عبر GPM أو Dolphin.  
4. **ربط Puppeteer** بعنوان التصحيح البعيد (remote debugging) للمتصفح داخل البروفايل.  
5. **فتح مسار التسجيل** في `src/gmail/creator.js` ومعالجة الحقول الأولية المدعومة بعد التحقق من الصفحة.
6. تسليم إدخال كلمة المرور والتحقق والموافقة وتأكيد الحساب والصفحات غير المعروفة إلى صاحب الحساب.
7. حفظ حالة المحاولة في `results.json` دون تخزين كلمات المرور أو رموز التحقق أو بيانات اعتماد البروكسي.
8. محاولة إيقاف البروفايل وتسجيل أي حالة إيقاف أو حذف تعذّر تأكيدها في `summary.json`.

بعد انتهاء كل المهام، يُكتب **ملخص التشغيلة** في `summary.json` (إحصائيات نجاح/فشل، المدة، إعدادات مختصرة).

---

## مخططات توضيحية

يعرض GitHub مخططات [Mermaid](https://mermaid.js.org/) تلقائياً داخل ملفات Markdown. إن لم تظهر لديك محلياً، افتح المستودع على GitHub أو استخدم إضافة معاينة تدعم Mermaid.

### السياق العام للنظام

```mermaid
flowchart TB
  subgraph Runtime["عملية Node.js src/index.js"]
    Q[processQueue حد التزامن]
    CA[createAccount لكل مهمة]
  end
  subgraph Profiles["واجهة البروفايل المضاد للبصمة"]
    GPM[GPM Login محلي]
    DOL[Dolphin Anty API]
  end
  subgraph Browser["Chrome حقيقي داخل البروفايل"]
    PU[Puppeteer عبر CDP]
    WEB[تسجيل accounts.google.com]
  end
  CFG[(إعدادات .env وnames.json وproxies.txt)]
  OUT[(results.json وsummary.json وlogs)]

  CFG --> Runtime
  Q --> CA
  CA --> GPM
  CA --> DOL
  GPM --> PU
  DOL --> PU
  PU --> WEB
  CA --> OUT
```

### تسلسل محاولة واحدة حتى التسليم

```mermaid
sequenceDiagram
  participant M as main / createAccount
  participant P as proxyManager
  participant N as nameGenerator
  participant Pr as بروفايل GPM أو Dolphin
  participant PP as صفحة Puppeteer
  participant G as createGmailAccount

  M->>P: getNextProxy
  M->>N: generateAccountData
  M->>Pr: createAndStartProfile + بروكسي
  Pr->>PP: getBrowser / getPage
  M->>G: createGmailAccount(page, data)
  G->>PP: الانتقال والتحقق من نموذج التسجيل
  G-->>M: يتطلب إكمالاً يدوياً
  M->>M: saveResult إلى results.json
  M->>Pr: stop
```

### مسار التسجيل داخل Gmail (منطقي)

```mermaid
flowchart TD
  A[createGmailAccount] --> B[الانتقال لصفحة التسجيل]
  B --> C{نموذج تسجيل تم التحقق منه}
  C -->|خطوة أولية مدعومة| D[ملء الاسم أو اسم المستخدم]
  D --> C
  C -->|تحقق أو موافقة أو حالة غير معروفة| E[تسجيل الحاجة إلى إكمال يدوي]
```

### جدول — نموذج التزامن

| المفهوم | الشرح في هذا المشروع |
|--------|----------------------|
| **مهمة حساب** | استدعاء واحد لـ `createAccount()` = دورة حياة بروفايل واحد. |
| **Thread في السجلات** | بادعة تسجيل فقط؛ التنفيذ الفعلي عبر `async` وليس خيوط نظام تشغيل. |
| **التزامن** | `processQueue` يحدُّ أقصى عدد مهام متزامنة بـ `threadsCount`. |
| **حالة مشتركة** | كل مهمة لها بروفايلها؛ `proxyManager` يتتبع أسطر البروكسي المستخدمة. |

---

## جدول الوحدات البرمجية (ملف ← مسؤولية)

| المسار | المسؤولية |
|--------|-----------|
| `src/index.js` | معاملات سطر الأوامر، طابور المهام، `saveResult`، ملخص `summary.json`. |
| `src/config.js` | تحميل `.env` / `.emv`، كائن `config`، تحذيرات التحقق. |
| `src/gmail/creator.js` | أتمتة واجهة التسجيل؛ التصدير الرئيسي `createGmailAccount`. |
| `src/gmail/page-detector.js` | كشف نوع شاشة Google؛ دوال انتظار العناصر. |
| `src/captcha/omo-handler.js` | التحقق من الإضافة، إدخال المفتاح، `setupOMOCaptchaExtension`. |
| `src/gpmlogin/client.js` | طلبات HTTP إلى GPM (إنشاء/تشغيل/إيقاف البروفايل، بصمة). |
| `src/gpmlogin/profile.js` | صنف `GPMLoginProfile` ومصنع `createAndStartProfile`. |
| `src/dolphin/client.js` | واجهة REST لـ Dolphin (بروفايلات، مجلدات، بروكسي). |
| `src/dolphin/profile.js` | صنف `DolphinProfile` ومصنع `createAndStartProfile`. |
| `src/gologin/client.js` | عميل GoLogin السحابي (اختياري، ملف كبير). |
| `src/gologin/profile.js` | صنف `GoLoginProfile` ومصنع `createAndStartProfile`. |
| `src/providers/sms-provider.js` | اختيار مزود SMS الموحّد (SMS Verification). |
| `src/providers/sms-verification-api.js` | دوال HTTP لمزود SMS Verification. |
| `src/providers/fivesim-api-legacy.js` | يرفض طلبات المحول القديم الذي يستخدم HTTP. |
| `src/utils/logger.js` | مستويات السجل، ملف يومي تحت `logs/`. |
| `src/utils/proxy-manager.js` | قراءة `config/proxies.txt` وتنسيقات البروكسي. |
| `src/utils/name-generator.js` | توليد هوية من `config/names.json`. |
| `src/utils/human-behavior.js` | حركة فأرة، تمرير، كتابة بتأخير بشري. |

---

## مرجع الدوال (شرح مختصر لكل دالة مصدَّرة أو método عام)

> الدوال **الداخلية** داخل `creator.js` لا تُستورد من ملفات أخرى؛ مذكورة في جدول منفصل للتوضيح فقط.

### `src/index.js`

| الدالة / الرمز | النوع | الوظيفة |
|----------------|-------|---------|
| `saveResult` | دالة | إلحاق سجل واحد في `results.json` مع وقت ISO. |
| `createAccount` | async | المسار الكامل: بروكسي → بيانات → بروفايل → `createGmailAccount` → حفظ → تنظيف. |
| `processQueue` | async | تشغيل مصفوفة من دوال async بدون معاملات مع حد أقصى للتزامن؛ إرجاع إحصائيات. |
| `main` | async | تحليل argv/env، بناء الطابور، استدعاء `processQueue`، كتابة `summary.json`. |
| التصدير الافتراضي | كائن | `{ createAccount, main }` للاستخدام البرمجي. |

### `src/config.js`

| الرمز | الوظيفة |
|-------|---------|
| `config` | كائن يضم `profileService`, `gpmlogin`, `dolphin`, `gologin`, `omocaptcha`, `smsVerify`, `app`. |
| `default` | نفس `config`. |

### `src/gmail/creator.js`

| الدالة | الوظيفة |
|--------|---------|
| `createGmailAccount(page, accountData, options)` | يعالج الخطوات الأولية المدعومة ويُرجع خطأ `MANUAL_SIGNUP_REQUIRED` مع المرحلة التي يتولى فيها صاحب الحساب المتابعة. |

### `src/gmail/page-detector.js`

| الدالة | الوظيفة |
|--------|---------|
| `detectGmailPage` | تقدير نوع شاشة التسجيل الحالية. |
| `waitForElement` | انتظار ظهور محدد CSS. |
| `elementExists` | فحص وجود عنصر. |
| `waitForPageLoad` | انتظار اكتمال التحميل. |
| *(داخلية)* `detectSignInPage`, `detectSignUpPage`, `detectVerificationPage`, `detectByClassNames`, `detectByElements` | مساعدات لـ `detectGmailPage`. |

### `src/captcha/omo-handler.js`

| الدالة | الوظيفة |
|--------|---------|
| `checkRecaptchaExtension` | التحقق من وجود إضافة الكابتشا. |
| `openOMOCaptchaExtension` | فتح واجهة الإضافة. |
| `setOMOCaptchaKeyViaAPI` / `enterOMOCaptchaKey` | يطلبان إعداد المفتاح يدوياً في الإضافة. |
| `clickRecaptchaRefreshButton` | تحديث عنصر الكابتشا. |
| `setupOMOCaptchaExtension` | تسلسل إعداد OMO قبل الحاجة للكابتشا. |

### `src/gpmlogin/client.js`

| الدالة | الوظيفة |
|--------|---------|
| `generateAndroidUserAgent` | توليد User-Agent أندرويد. |
| `generateAndroidFingerprint` | بصمة جهاز للبروفايل. |
| `checkGPMConnection` | فحص الاتصال بـ GPM. |
| `createProfile` | إنشاء بروفايل مع بروكسي اختياري. |
| `startProfile` | تشغيل البروفايل وإرجاع عنوان التصحيح. |
| `stopProfile` | إيقاف مع إعادة محاولات. |
| `deleteProfile` | حذف البروفايل. |
| `getProfile` | جلب بيانات البروفايل. |

### صنف `GPMLoginProfile` في `src/gpmlogin/profile.js`

| الطريقة | الوظيفة |
|---------|---------|
| `start` | تشغيل البروفايل وحل نقطة WebSocket/CDP. |
| `getBrowser` | الاتصال عبر `puppeteer.connect`. |
| `getPage` | الحصول على تبويب/صفحة للعمل. |
| `stop` / `delete` | إيقاف أو حذف البروفايل. |
| `injectAntiDetectionScripts` | حقن سكربتات تخفيف كشف الأتمتة. |
| `createAndStartProfile` *(مصدَّرة)* | إنشاء ثم تشغيل وإرجاع كائن الجلسة. |

### `src/dolphin/client.js` (دوال مصدَّرة)

| الدالة | الوظيفة |
|--------|---------|
| `checkDolphinConnection` | التحقق من المفتاح والوصول. |
| `createProfile` / `startProfile` / `stopProfile` / `deleteProfile` / `getProfile` | دورة حياة البروفايل. |
| `updateProfileProxy` | تطبيق بروكسي على بروفايلات. |
| `getFolderList`, `getAllFolders`, `findFolderByName`, `createFolder`, `getFirstAvailableFolder`, `getOrCreateFolder` | إدارة المجلدات. |

### صنف `DolphinProfile` في `src/dolphin/profile.js`

| الطريقة | الوظيفة |
|---------|---------|
| `start`, `getBrowser`, `getPage`, `stop`, `delete` | مثل GPM من ناحية الدور. |
| `createAndStartProfile` *(مصدَّرة)* | مصنع جاهز لـ Dolphin. |

### صنف `GoLoginProfile` في `src/gologin/profile.js`

| الطريقة | الوظيفة |
|---------|---------|
| `start`, `getBrowser`, `getPage`, `stop`, `delete` | دورة حياة GoLogin. |
| `createAndStartProfile` *(مصدَّرة)* | مصنع عند استخدام مسار GoLogin. |

### `src/gologin/client.js` — `GoLoginClient` (التصدير الافتراضي)

| الطريقة | الوظيفة |
|---------|---------|
| `request` | HTTP موثّق لـ API. |
| `getProfiles`, `getProfile`, `createProfile`, `updateProfile`, `updateProfileProxy` | إدارة البروفايلات. |
| `startProfile`, `stopProfile`, `deleteProfile` | تشغيل وإيقاف وحذف. |
| `testProxy`, `createProfileWithProxy` | اختبار بروكسي وإنشاء مدمج. |

### `src/providers/sms-verification-api.js`

| الدالة | الوظيفة |
|--------|---------|
| `getSmsVerifyBalance` | الرصيد. |
| `getSmsVerifyCountries`, `getSmsVerifyPrices`, `getSmsVerifyServices` | استعلامات الكتالوج/الأسعار. |
| `buySmsVerifyNumber`, `buySmsVerifyNumberV2` | شراء رقم لخدمة معيّنة. |
| `checkSmsVerifyOrder` | حالة الطلب. |
| `setSmsVerifyStatus` | تحديث حالة الطلب. |
| `cancelSmsVerifyOrder`, `finishSmsVerifyOrder`, `retrySmsVerifyOrder` | إدارة دورة الرقم. |
| `getSmsVerifyActivations` | قائمة التفعيلات. |
| `waitForSmsVerifyCode` | انتظار وصول الرمز. |
| `buyNumberAndGetSMS` | شراء + انتظار الرمز في استدعاء واحد معقّد. |

### `src/providers/sms-provider.js`

| الرمز | الوظيفة |
|-------|---------|
| `getBalance`, `buyNumber`, `buyNumberAndGetSMS` | واجهة موحّدة بعد تحميل المزود. |
| `getOrderStatus`, `waitForSMS` | متابعة الطلب والرسالة. |
| `cancelOrder`, `finishOrder`, `requestResend`, `setOrderStatus` | إدارة الطلب. |
| `reportNumberUsed` | واجهة توافق للمزود. |
| `getServiceName`, `getProviderType` | للسجلات والتشخيص. |
| `SMS_PROVIDER_INFO` | `{ current: SMS_PROVIDER }`. |
| أسماء بديلة | `buySmsVerifyNumber`, `waitForSmsVerifyCode`, … تطابق الواجهة القديمة. |
| `SMS_VERIFY_COUNTRIES` | إعادة تصدير ثوابت الدول. |

### `src/utils/logger.js`

| الرمز | الوظيفة |
|-------|---------|
| `logger` / `default` | `error`, `warn`, `info`, `debug` — للكونسول وملف السجل اليومي. |
| *(داخلية)* `formatMessage`, `shouldLog`, `writeLog` | تنسيق وفلترة المستوى. |

### `ProxyManager` في `src/utils/proxy-manager.js`

| الطريقة | الوظيفة |
|---------|---------|
| `loadProxies` | قراءة الملف. |
| `getNextProxy` | اختيار عشوائي من غير المستخدم. |
| `markAsUsed`, `releaseProxy`, `reset` | تتبع التوفر. |
| `getGPMLoginFormat`, `getGoLoginFormat`, `getStringFormat` | تحويل للصيغ المطلوبة وللسجلات. |
| `getAvailableCount` | عدد تقريبي للبروكسيات المتاحة. |

### `NameGenerator` في `src/utils/name-generator.js`

| الطريقة | الوظيفة |
|---------|---------|
| `loadNames` | تحميل JSON. |
| `getRandomName` | اسم أول عشوائي. |
| `generateUsername` | جزء محلي مقترح للبريد. |
| `generatePassword` | كلمة مرور قوية. |
| `generateAccountData` | كائن حساب كامل جاهز للتسجيل. |

### `src/utils/human-behavior.js`

| الدالة | الوظيفة |
|--------|---------|
| `randomDelay`, `getHumanDelay` | زمن عشوائي مناسب لنوع الحركة. |
| `humanSleep` | تأخير غير ثابت. |
| `humanMouseMove`, `getElementCenter` | مسار فأرة منحنٍ نحو هدف. |
| `humanClick`, `humanClickAt` | نقرة مع حركة وتوقيت. |
| `humanScroll`, `humanScrollToElement` | تمرير تدريجي. |
| `explorePageRandomly` | تفاعلات عشوائية خفيفة بالصفحة. |
| `humanType` | كتابة حرف بحرف مع أخطاء اختيارية. |
| `idleMouseMovement`, `simulateReading`, `performRandomAction` | محاكاة خمول المستخدم. |
| `humanWait` | انتظار مع إجراءات عشوائية أحياناً. |
| `simulateTabSwitch` | محاكاة تبديل نافذة/تركيز. |
| *(داخلية)* `bezierPoint`, `cubicBezierPoint`, `generateMousePath` | حساب مسار الفأرة. |

---

## المخرجات والسجلات

تُحفظ هذه الملفات داخل [مجلد حالة التطبيق](ENV_VARIABLES.md#configuration-and-local-state).

| الملف / المجلد | المحتوى |
|----------------|---------|
| `results.json` | سجل لكل محاولة (نجاح أو فشل) مع الطابع الزمني |
| `summary.json` | ملخص آخر تشغيلة كاملة |
| `logs/` | سجلات تفصيلية حسب `LOG_LEVEL` |

---

## الإصدارات (Releases) وحزمة GitHub Packages

في صفحة المستودع يظهر **Releases** و**Packages** في الشريط الجانبي. الروابط المباشرة:

| المنطقة | الرابط | الفائدة |
|---------|--------|---------|
| **Releases** | […/releases](https://github.com/code-root/gmail-account-creator/releases) | إصدارات مُوسومة، ملاحظات، وملف **`.tgz`** من `npm pack` عند دفع وسم `v*` |
| **Packages** | [npm package](https://github.com/code-root/gmail-account-creator/pkgs/npm/gmail-account-creator) | تثبيت **`@code-root/gmail-account-creator`** بعد `npm publish` |

اسم الحزمة على سجل npm الخاص بـ GitHub: **`@code-root/gmail-account-creator`** (نطاق الاسم يطابق مالك المستودع `code-root`).

### الخيار أ — إصدار تلقائي (مُستحسن)

1. حدّث `version` في `package.json` وادفع إلى `main`.  
2. `git tag v1.0.1 && git push origin v1.0.1`  
3. سير العمل **Release** يبني الحزمة ويُنشئ صفحة إصدار مع الملحق.  
4. عند **نشر** الإصدار، سير **Publish to GitHub Packages** ينشر النسخة على سجل npm لدى GitHub.

### الخيار ب — من واجهة GitHub: «Create a new release»

1. افتح [**Releases**](https://github.com/code-root/gmail-account-creator/releases) ثم **Create a new release** (أو **Draft a new release**).  
2. اختر وسمًا (أنشئ وسمًا جديدًا `v1.0.x` على `main` إن لزم)، اكتب العنوان والملاحظات.  
3. انشر الإصدار.  
   - **ملاحظة:** ملف **`.tgz`** يُرفَق تلقائياً عند **دفع الوسم** (الخيار أ). إن أنشأت الإصدار يدوياً فقط من الواجهة دون دفع وسم مطابق، شغّل `npm pack` محلياً وأرفق الملف، أو ادفع الوسم لاحقاً لتشغيل سير العمل.

#### إذا كانت GitHub Actions معطّلة (مثلاً بسبب الفوترة)

بدون Actions يمكنك: (1) تشغيل `npm pack` ورفع الملف من **Create a new release** أو عبر `gh release create`؛ (2) تنفيذ `npm publish` محلياً بتوكن يملك `write:packages` وسجل `npm.pkg.github.com` — راجع [توثيق GitHub](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry).

### التثبيت من GitHub Packages

أضف هذه الإعدادات إلى إعداد npm الخاص بالمستخدم (عادةً `~/.npmrc`). حمّل `GITHUB_PACKAGES_TOKEN` من مخزن بيانات الاعتماد إلى بيئة التشغيل قبل تشغيل npm. استخدم [رمز وصول](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry) يملك `read:packages`.

```text
@code-root:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
```

ثم:

```bash
npm install @code-root/gmail-account-creator
```

تشغيل عبر `npx` أو الأمر العام بعد التثبيت الشامل:

```bash
npx @code-root/gmail-account-creator
gmail-account-creator
```

### النشر التلقائي

عند **نشر** إصدار GitHub (Release published)، سير العمل **Publish to GitHub Packages** (`.github/workflows/publish-github-packages.yml`) ينفّذ `npm publish` باستخدام `GITHUB_TOKEN`.

---

## سير عمل GitHub المقترح (حسب التقنية)

المشروع يستخدم **Node + ESM** بدون اختبارات Jest مدمجة في `package.json`. السيرات المضمّنة:

1. **CI** يثبّت التبعيات ويفحص الصياغة ويشغّل اختبارات الأمان عند الدفع أو فتح طلب دمج — `.github/workflows/ci.yml`
2. **Release** يشغّل اختبارات الأمان عند دفع وسم `v*` قبل إرفاق حزمة npm — `.github/workflows/release.yml`
3. **نشر الحزمة** يشغّل اختبارات الأمان قبل نشر الحزمة عند نشر إصدار — `.github/workflows/publish-github-packages.yml`
4. **Dependabot (اختياري):** تحديثات أسبوعية لـ `npm`.  
5. **عدم رفع أسرار:** التأكد أن `.env` غير مرفوع.

شغّل `npm run test:security` من نسخة من الشيفرة المصدرية بعد تثبيت التبعيات. للتحقق من إصدار مثبّت، شغّل الاختبارات من وسم الإصدار المطابق.

---

## المطوّر والشركة والتواصل

| | |
|---|---|
| **المطوّر** | مصطفى الباجوري (Mostafa Al-Bagouri) |
| **الشركة** | **[Storage TE](http://storage-te.com/)** |
| **واتساب** | [+20 100 199 5914](https://wa.me/201001995914) |

---

## دعم المشروع (Support)

إذا كان هذا المشروع مفيداً لك، يمكنك — اختيارياً — دعم الصيانة والتطوير عبر أي قناة تناسبك.

| القناة | طريقة الدعم |
|--------|-------------|
| **PayPal** | [paypal.me/sofaapi](https://paypal.me/sofaapi) |
| **Binance Pay / UID** | **1138751298** — من تطبيق Binance (Pay / تحويل داخلي عند توفره). |
| **إيداع Binance (الويب)** | [إيداع العملات المشفرة (Binance)](https://www.binance.com/en/my/wallet/account/main/deposit/crypto) — سجّل الدخول، اختر الأصل، ثم شبكة **BSC (BEP20)**. |
| **عنوان BSC (للنسخ)** | `0x94c5005229784d9b7df4e7a7a0c3b25a08fd57bc` |

> **الشبكة:** استخدم **BSC (BEP-20)** فقط. هذا العنوان مخصص لـ **USDT (BEP-20)** و**BTC على BSC** (Binance-Peg / «BTC» على BSC داخل التطبيق)، بما يتوافق مع شاشات الإيداع في Binance. **لا ترسل** **بتكوين أصلي على السلسلة (on-chain BTC)**، ولا **ERC-20**، ولا **NFTs** إلى هذا العنوان.

### رموز QR للإيداع (امسح ضوئياً في Binance أو أي محفظة BSC)

| USDT · BSC | BTC · BSC |
|------------|-----------|
| ![USDT deposit QR — BSC](assets/deposit-usdt-bsc.jpeg) | ![BTC on BSC deposit QR](assets/deposit-btc-bsc.jpeg) |

الصور محفوظة في [`assets/`](assets/) بأسماء ثابتة — راجع [`assets/README.md`](assets/README.md). النسخة الإنجليزية: [Support this project](README.md#support-this-project).

---

## تحذير قانوني وأخلاقي

أتمتة إنشاء حسابات Google قد **تخالف شروط استخدام Google** والقوانين المحلية. استخدم المشروع فقط في بيئات تملكها، وبإذن صريح، ولأغراض مشروعة (مثل اختبار أنظمتك الداخلية). المسؤولية الكاملة عن الاستخدام تقع على المستخدم.

---

## مراجع سريعة داخل المستودع

- [`USAGE.md`](USAGE.md) — أمثلة أوامر إضافية  
- [`ENV_VARIABLES.md`](ENV_VARIABLES.md) — شرح متغيرات البيئة والمزودين  
- [`SETUP.md`](SETUP.md) — ملاحظات إعداد (استبدل أي مفاتيح وهمية/قديمة بمفاتيحك الخاصة)  
- [`GITHUB_SETUP.md`](GITHUB_SETUP.md) — إعداد GitHub إن وُجد  

الرابط العام للمشروع: [https://github.com/code-root/gmail-account-creator](https://github.com/code-root/gmail-account-creator)
