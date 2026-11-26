/**
 * Name Generator
 * توليد الأسماء العشوائية
 */

import { randomInt } from 'node:crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import logger from './logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const NAMES_FILE = path.join(__dirname, '../../config/names.json');

class NameGenerator {
    constructor() {
        this.names = { female: [], male: [] };
        this.loadNames();
    }

    /**
     * Load names from JSON file
     * تحميل الأسماء من ملف JSON
     */
    loadNames() {
        try {
            if (!fs.existsSync(NAMES_FILE)) {
                logger.error('Names file not found');
                return;
            }

            const content = fs.readFileSync(NAMES_FILE, 'utf8');
            this.names = JSON.parse(content);
            logger.info(`Loaded ${this.names.female.length} female and ${this.names.male.length} male names`);
        } catch (error) {
            logger.error('Error loading names', { error: error.message });
        }
    }

    /**
     * Get random name
     * الحصول على اسم عشوائي
     */
    getRandomName(gender = null) {
        if (!gender) {
            gender = Math.random() < 0.5 ? 'female' : 'male';
        }

        const nameList = this.names[gender] || [];
        if (nameList.length === 0) {
            return gender === 'female' ? 'Fatima' : 'Ahmed';
        }

        return nameList[Math.floor(Math.random() * nameList.length)];
    }

    /**
     * Generate random username
     * توليد اسم مستخدم عشوائي
     */
    generateUsername(firstName, lastName = null) {
        const cleanFirst = String(firstName || 'user').toLowerCase().replace(/[^a-z0-9]/g, '');
        const cleanLast = lastName ? String(lastName).toLowerCase().replace(/[^a-z0-9]/g, '') : '';
        const randomNum = 10 + Math.floor(Math.random() * 9990);
        const year = 1990 + Math.floor(Math.random() * 30);
        
        if (cleanLast) {
            return `${cleanFirst}${cleanLast}${year}${randomNum}`;
        }
        
        return `${cleanFirst}${randomNum}${year}`;
    }

    /**
     * Generate strong password
     * توليد كلمة مرور قوية
     */
    generatePassword(length = 16) {
        const groups = [
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'abcdefghijklmnopqrstuvwxyz',
            '0123456789',
            '!@#$%^&*'
        ];
        const chars = groups.join('');
        const arr = groups.map(group => group[randomInt(group.length)]);
        
        for (let i = arr.length; i < length; i++) {
            arr.push(chars[randomInt(chars.length)]);
        }
        
        // Unbiased Fisher-Yates shuffle
        for (let i = arr.length - 1; i > 0; i--) {
            const j = randomInt(i + 1);
            const tmp = arr[i];
            arr[i] = arr[j];
            arr[j] = tmp;
        }
        return arr.join('');
    }

    /**
     * Generate full account data
     * توليد بيانات حساب كاملة
     */
    generateAccountData() {
        const gender = Math.random() < 0.5 ? 'female' : 'male';
        const firstName = this.getRandomName(gender);
        let lastName = this.getRandomName(gender);
        if (lastName === firstName) {
            lastName = this.getRandomName(gender);
        }
        const username = this.generateUsername(firstName, lastName);
        const password = this.generatePassword();
        const email = `${username}@gmail.com`;

        return {
            firstName,
            lastName,
            fullName: `${firstName} ${lastName}`,
            username,
            email,
            password,
            gender
        };
    }
}

export default new NameGenerator();


