# دليل الاستخدام

## تشغيل البوت

### الطريقة 1: استخدام متغيرات البيئة

أضف القيم في ملف `.env` داخل [مجلد حالة التطبيق](ENV_VARIABLES.md#configuration-and-local-state).
```env
ACCOUNTS_COUNT=10
THREADS_COUNT=3
```

ثم شغّل:
```bash
npm start
```

### الطريقة 2: استخدام معاملات سطر الأوامر

```bash
# إنشاء 10 حسابات بـ 3 threads متزامنة
npm start -- --accounts=10 --threads=3

# أو بشكل مختصر
npm start -- -a=10 -t=3
```

### الطريقة 3: استخدام متغيرات البيئة مباشرة

```bash
ACCOUNTS_COUNT=10 THREADS_COUNT=3 npm start
```

## أمثلة

### مثال 1: إنشاء حساب واحد
```bash
npm start
# أو
npm start -- --accounts=1 --threads=1
```

### مثال 2: إنشاء 5 حسابات بشكل متسلسل (thread واحد)
```bash
npm start -- --accounts=5 --threads=1
```

### مثال 3: إنشاء 20 حساب بـ 5 threads متزامنة
```bash
npm start -- --accounts=20 --threads=5
```

### مثال 4: إنشاء 100 حساب بـ 10 threads
```bash
npm start -- --accounts=100 --threads=10
```

## النتائج وحالة التسليم اليدوي

عندما يسجّل التطبيق `MANUAL_SIGNUP_REQUIRED`، أكمل التحقق والموافقة وتأكيد هوية الحساب في متصفح موثوق. راجع `summary.json` لأي بروفايل تعذّر تأكيد إيقافه.

1. تأكد من وجود عدد كافٍ من البروكسيات في `config/proxies.txt` داخل مجلد الحالة عندما يتطلب وضع البروفايل بروكسي.
   - إذا كان لديك 5 بروكسيات وطلبت 10 threads، سيتم إعادة استخدام البروكسيات

2. **الأداء**: 
   - عدد threads أكبر = أسرع لكن استهلاك موارد أكبر
   - عدد threads أقل = أبطأ لكن أكثر استقراراً

3. يحفظ التطبيق `results.json` و`summary.json` والسجلات `logs/` في مجلد الحالة.

## إعدادات افتراضية

- `ACCOUNTS_COUNT=1` (حساب واحد)
- `THREADS_COUNT=1` (thread واحد)

اضبط عدد المحاولات والتزامن على أعداد صحيحة موجبة ضمن نطاق الأعداد الصحيحة الآمنة في JavaScript. يحدّ التطبيق التزامن بعدد المحاولات المطلوبة.


