/**
 * List the folders available to the configured Dolphin Anty account.
 */
import config from '../src/config.js';
import { getAllFolders } from '../src/dolphin/client.js';
import { ControllerRequestError } from '../src/utils/controller-request.js';
import { ControllerUrlError } from '../src/utils/controller-url.js';

function terminalValue(value) {
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
    if (typeof value !== 'string') return '—';
    return value.replace(/\\|[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, character => {
        if (character === '\\') return '\\\\';
        const codePoint = character.codePointAt(0).toString(16).padStart(4, '0');
        return `\\u{${codePoint}}`;
    });
}

async function listAllFolders() {
    console.log('🔍 جارٍ جلب قائمة المجلدات...');
    const apiKeyConfigured = config.dolphin.apiKey.trim() !== '';
    console.log(`🔑 DOLPHIN_API_KEY configured: ${apiKeyConfigured}`);

    if (!apiKeyConfigured) {
        console.error('❌ أضف DOLPHIN_API_KEY إلى ملف .env.');
        process.exitCode = 1;
        return;
    }

    const allFolders = await getAllFolders();
    console.log(`\n✅ تم العثور على ${allFolders.length} مجلد.\n`);
    if (allFolders.length === 0) {
        console.log('⚠️  لا توجد مجلدات. يمكنك إنشاء مجلد جديد من Dolphin Anty.');
        return;
    }

    allFolders.forEach((folder, index) => {
        const folderId = terminalValue(folder?.id ?? folder?.folderId);
        const folderName = terminalValue(folder?.folderName ?? folder?.name ?? 'بدون اسم');
        const folderColor = terminalValue(folder?.folderColor ?? folder?.color ?? '#3370FF');
        const resourceCount = terminalValue(folder?.resourceCount ?? folder?.browserProfilesData?.length ?? 0);

        console.log(`📁 المجلد ${index + 1}`);
        console.log(`   الاسم: ${folderName}`);
        console.log(`   ID: ${folderId}`);
        console.log(`   اللون: ${folderColor}`);
        console.log(`   عدد البروفايلات: ${resourceCount}\n`);
    });

    console.log('📝 لاستخدام مجلد محدد، أضف السطر التالي إلى ملف .env.');
    console.log('DOLPHIN_FOLDER_ID=<folder_id_here>');
}

await listAllFolders().catch(error => {
    console.error('❌ خطأ في جلب المجلدات.');
    if (error instanceof ControllerRequestError || error instanceof ControllerUrlError) {
        console.error(`   ${error.message}`);
    }
    if (error?.status === 401 || error?.status === 403) {
        console.error('   تحقق من صلاحيات قراءة المجلدات لمفتاح Dolphin Anty.');
    }
    process.exitCode = 1;
});
