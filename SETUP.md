# إعداد المشروع

## إضافة API Keys

أنشئ ملف `.env` في مجلد الحالة باتباع [خطوات إعداد الملفات الخاصة](README_AR.md#2-إنشاء-ملفات-الإعدادات-الخاصة) ثم أضف الإعدادات التالية.

```env
# GoLogin API Configuration (if you use GoLogin paths — optional for GPM/Dolphin-only flows)
GOLOGIN_API_KEY=your_gologin_api_key_here

# Optional settings for separate SMS Verification library use
SMS_VERIFY_API_KEY=your_sms_verify_api_key_here
SMS_VERIFY_LANG=ru

# Application Settings
LOG_LEVEL=info
MAX_RETRIES=3

# Account Creation Settings
ACCOUNTS_COUNT=1      # عدد الحسابات المراد إنشاؤها
THREADS_COUNT=1       # عدد الـ threads المتزامنة
```

## تثبيت التبعيات

```bash
npm install
```

## تشغيل المشروع

```bash
npm start
```

## ملاحظات

- أضف البروكسيات في `config/proxies.txt` داخل مجلد الحالة عندما يتطلب وضع البروفايل بروكسي.
- ضع مفاتيحك الحقيقية في `.env` فقط ولا ترفعها إلى Git
- أكمل التحقق والموافقة وتأكيد هوية الحساب يدوياً عند ظهور `MANUAL_SIGNUP_REQUIRED`.
- يمكن تحديد عدد الحسابات والـ threads من `.env` أو من سطر الأوامر
- راجع `USAGE.md` لأمثلة مفصلة

