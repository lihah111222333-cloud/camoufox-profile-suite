# إعداد رفع المشروع على GitHub Private Repository

## الخطوات:

### 1. إنشاء Repository جديد على GitHub

1. اذهب إلى https://github.com/new
2. اختر اسم للمشروع (مثلاً: `gmail-account-creator`)
3. اختر **Private** (مهم جداً!)
4. **لا** تضع علامة على Initialize with README
5. اضغط **Create repository**

### 2. رفع المشروع

بعد إنشاء المستودع، عيّن `expected_origin` إلى عنوان المستودع المطلوب ونفّذ الكتلة كاملة. استخدم عنوان HTTPS أو SSH. يتوقف التسلسل إذا فشل الفحص أو تعذّر إعداد `origin` أو اختلف عنوان الدفع الفعلي.

يفحص سكريبت الدفع الأول سجل أمثلة OpenAPI في الفرع قبل تجهيز الالتزام. إذا أبلغ عن أمثلة قديمة، نسّق مع مالك المستودع لمعالجة السجل قبل نقله إلى وجهة جديدة.

```bash
expected_origin=https://github.com/YOUR_USERNAME/REPO_NAME.git
bash PUSH_TO_GITHUB.sh &&
  git remote add origin "$expected_origin" &&
  push_origin=$(git remote get-url --push --all origin) &&
  test "$push_origin" = "$expected_origin" &&
  git branch -M main &&
  git push -u origin main
```

### 3. التحقق من الملفات الحساسة

تأكد من أن الملفات التالية **غير موجودة** في الـ repository:
- `.env`
- `.npmrc` إذا احتوى على بيانات اعتماد
- `config/proxies.txt`
- `email.txt`
- `gmlogin.txt`
- `results.json`
- `summary.json`
- `logs/`
- ملفات تعريف المتصفح، بما فيها مجلد `CAMOUFOX_STORAGE_DIR` المخصص
- ملفات التقاط الحركة مثل `traffic.har`

### 4. إنشاء ملف .env.example

أنشئ ملف `.env.example` يحتوي على المتغيرات المطلوبة بدون القيم الحساسة:

```env
# GPM Login API URL
GPM_API_URL=http://127.0.0.1:14517

# OMO Captcha API Key
OMOCAPTCHA_KEY=your_omocaptcha_key_here

# SMS Verification API Key
SMS_VERIFY_API_KEY=your_sms_verify_key_here

# Application Settings
ACCOUNTS_COUNT=1
THREADS_COUNT=1
LOG_LEVEL=info
TEST_PROXY=true
```

### 5. تحديث README.md

تأكد من تحديث README.md ليشمل:
- وصف المشروع
- متطلبات التشغيل
- تعليمات الإعداد
- كيفية الاستخدام

## ملاحظات أمنية:

⚠️ **مهم جداً:**
- تأكد من أن الـ repository **Private**
- لا ترفع أي ملفات تحتوي على:
  - API keys
  - Proxies
  - Passwords
  - Personal data
- احتفظ بـ `.env` وملفات الاعتماد في [مجلد حالة التطبيق](ENV_VARIABLES.md#configuration-and-local-state).
- احتفظ بقواعد تجاهل الملفات الحساسة في `.gitignore`.

## التحقق من الإصدار قبل نشره

يشير الوسم المحلي `v1.0.0` إلى الالتزام `6392824`. تتضمن نسخة OpenAPI في ذلك الالتزام أمثلة قديمة لقيم ملفات تعريف الارتباط ومفتاح ورمز مميز. يرفض فاحص الإصدار الحالي هذا الوسم. يلزم التنسيق بشأن الوسم والسجل السابقين، والتحقق من حالة النشر وصلاحية بيانات الاعتماد لدى مالك المستودع. أبقِ تفاصيل القيم خارج التقارير والإصدارات.

حضّر التزامًا خضع للمراجعة يتضمن إصدارًا جديدًا في `package.json`. نفّذ الفحوص التالية من نسخة عمل نظيفة لذلك الالتزام، واستبدل `v1.0.1` بالوسم المطابق للإصدار:

```bash
set -o pipefail
node scripts/check-distribution.mjs tag v1.0.1 &&
  node scripts/check-distribution.mjs source HEAD &&
  npm pack --json | node scripts/check-distribution.mjs archive
```

نفّذ الفحوص قبل دفع الوسم أو النشر من واجهة GitHub. يُنشئ GitHub أرشيف المصدر من الالتزام الذي يشير إليه الوسم، ويمكن أن يصبح متاحًا عند دفع الوسم قبل انتهاء سير العمل. افحص السجل كذلك إذا كانت الوجهة جديدة. احتفظ بالوسم والسجل الحاليين إلى أن ينسق المالك بشأنهما.

## إذا رفعت ملفًا حساسًا بالخطأ

1. ألغِ بيانات الاعتماد المكشوفة أو دوّرها فورًا، بما فيها كلمات مرور الوكلاء والرموز المميزة. أبطل جلسات المتصفح المكشوفة أيضًا.
2. أزل الملف من النسخة الحالية وأبقِه ضمن قواعد التجاهل. على سبيل المثال، أبقِ `config/proxies.txt` محليًا وأخرجه من الفهرس:

   ```bash
   git rm --cached -- config/proxies.txt
   git commit -m "Remove exposed proxy configuration"
   ```

3. انشر الالتزام وفق إجراءات المستودع. تظل القيم القديمة في الالتزامات السابقة. نسّق مع مسؤولي المستودع لتنظيف الفروع والوسوم المتأثرة وإزالة مواد الإصدار والنسخ المتاحة. نسّق مع أصحاب النسخ المستنسخة والمتفرعة لاستبدال النسخ القديمة. قد تبقى للبيانات المنشورة نسخ محفوظة أو مُنزَّلة، لذا أبقِ بيانات الاعتماد القديمة مُلغاة.
