import { requireControllerProfileId } from './controller-id.js';
import logger from './logger.js';

function cleanupError(profileId, profileCleanup, message, cause) {
    return Object.assign(new Error(message, { cause }), { profileId, profileCleanup });
}

export default class ManagedProfile {
    #client;
    #addressField;
    #startBrowser;
    #starting = null;
    #stopping = null;
    #deleting = null;

    constructor(profileId, client, addressField, address, startBrowser) {
        Object.defineProperty(this, 'profileId', {
            value: requireControllerProfileId(profileId),
            enumerable: true
        });
        this.browser = null;
        this.page = null;
        this.#client = client;
        this.#addressField = addressField;
        this.#startBrowser = startBrowser;
        this[addressField] = address;
    }

    async start() {
        while (this.#stopping) await this.#stopping;
        if (this.#deleting) throw new Error('Managed profile deletion is in progress');
        if (this.#starting) return this.#starting;
        if (this.browser) return this;

        this.#starting = Promise.resolve().then(this.#startBrowser).catch(async error => {
            await this.#detachBrowser();
            throw error;
        }).finally(() => {
            this.#starting = null;
        });
        return this.#starting;
    }

    async getBrowser() {
        await this.start();
        return this.browser;
    }

    async getPage() {
        const browser = await this.getBrowser();
        if (!this.page) {
            const pages = await browser.pages();
            this.page = pages[0] || await browser.newPage();
        }
        return this.page;
    }

    async #detachBrowser() {
        const browser = this.browser;
        this.browser = null;
        this.page = null;
        this[this.#addressField] = null;

        try {
            await browser?.disconnect();
        } catch {
            logger.warn('Could not detach the managed browser connection', { profileId: this.profileId });
        }
    }

    stop() {
        this.#stopping ??= Promise.resolve().then(async () => {
            // Wait for an in-flight start to hand off its browser before stopping by ID.
            await this.#starting?.catch(() => {});
            await this.#detachBrowser();
            try {
                if (await this.#client.stopProfile(this.profileId) === true) return true;
            } catch {
                // The controller did not confirm shutdown.
            }
            logger.warn('Managed profile shutdown unconfirmed', { profileId: this.profileId });
            return false;
        }).finally(() => {
            this.#stopping = null;
        });
        return this.#stopping;
    }

    delete() {
        this.#deleting ??= this.#delete().finally(() => {
            this.#deleting = null;
        });
        return this.#deleting;
    }

    async #delete() {
        if (await this.stop() !== true) {
            throw cleanupError(this.profileId, 'stop-unconfirmed', 'Managed profile shutdown unconfirmed');
        }
        let cause;
        try {
            if (await this.#client.deleteProfile(this.profileId) === true) return true;
        } catch (error) {
            cause = error;
        }
        throw cleanupError(this.profileId, 'delete-unconfirmed', 'Managed profile deletion unconfirmed', cause);
    }
}

export async function rollbackNewManagedProfile(profile, cause) {
    let profileCleanup = 'deleted';
    try {
        await profile.delete();
    } catch (error) {
        profileCleanup = error.profileCleanup ?? 'stop-unconfirmed';
    }
    logger.warn('Managed profile initialization failed', { profileId: profile.profileId, profileCleanup });
    return cleanupError(profile.profileId, profileCleanup, 'Managed profile initialization failed', cause);
}
