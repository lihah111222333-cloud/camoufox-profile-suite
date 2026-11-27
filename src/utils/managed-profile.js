import { requireControllerProfileId } from './controller-id.js';
import logger from './logger.js';

function cleanupError(profileId, profileCleanup, message, cause) {
    return Object.assign(new Error(message, { cause }), { profileId, profileCleanup });
}

export default class ManagedProfile {
    #client;
    #addressField;
    #borrowedAddress;
    #startBrowser;
    #starting = null;
    #startCancellation = null;
    #stopping = null;
    #deleting = null;
    #recycling = null;
    #recycleDispatched = false;
    #stopConfirmed = false;
    #deleted = false;
    #ownedPages = new Set();
    #openingPage = null;

    constructor(profileId, client, addressField, address, startBrowser) {
        Object.defineProperty(this, 'profileId', {
            value: requireControllerProfileId(profileId),
            enumerable: true
        });
        this.browser = null;
        this.page = null;
        // A caller-supplied debugger address does not establish which REST controller owns the profile.
        this.#borrowedAddress = address || null;
        this.#client = this.#borrowedAddress ? null : client;
        this.#addressField = addressField;
        this.#startBrowser = startBrowser;
        this[addressField] = address;
    }

    async start({ signal } = {}) {
        signal?.throwIfAborted();
        while (this.#stopping) await this.#stopping;
        signal?.throwIfAborted();
        if (this.#deleted) throw new Error('Managed profile has been deleted');
        if (this.#deleting) throw new Error('Managed profile deletion is in progress');
        if (this.#recycling) throw new Error('Managed profile recycling has been requested');
        if (this.#starting) return this.#starting;
        if (this.browser) return this;

        const cancellation = new AbortController();
        const abort = () => cancellation.abort(signal.reason);
        signal?.addEventListener('abort', abort, { once: true });
        this.#startCancellation = cancellation;
        this.#starting = Promise.resolve().then(async () => {
            cancellation.signal.throwIfAborted();
            this.#stopConfirmed = false;
            const profile = await this.#startBrowser(this.#client, this.#borrowedAddress, cancellation.signal);
            cancellation.signal.throwIfAborted();
            return profile;
        }).catch(async error => {
            await this.#detachBrowser();
            throw error;
        }).finally(() => {
            signal?.removeEventListener('abort', abort);
            this.#startCancellation = null;
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
            if (!browser) throw new Error('Managed browser is unavailable');
            const pages = await browser.pages();
            if (this.browser !== browser) throw new Error('Managed browser was detached');
            const page = pages[0] ?? await this.createOwnedPage();
            if (this.browser !== browser) throw new Error('Managed browser was detached');
            this.page = page;
        }
        return this.page;
    }

    async createOwnedPage() {
        const browser = this.browser;
        if (!browser) throw new Error('Managed browser is unavailable');
        this.#openingPage ??= browser.newPage().then(page => {
            this.#ownedPages.add(page);
            return page;
        }).finally(() => {
            this.#openingPage = null;
        });
        return this.#openingPage;
    }

    async #detachBrowser() {
        const browser = this.browser;
        this.browser = null;
        this.page = null;
        this[this.#addressField] = null;

        await this.#openingPage?.catch(() => {});
        for (const page of this.#ownedPages) {
            try {
                if (!page.isClosed()) await page.close();
            } catch {
                logger.warn('Could not close a page opened by the profile manager', { profileId: this.profileId });
            }
        }
        this.#ownedPages.clear();

        try {
            await browser?.disconnect();
        } catch {
            logger.warn('Could not detach the managed browser connection', { profileId: this.profileId });
        }
    }

    stop() {
        this.#stopping ??= Promise.resolve().then(async () => {
            this.#startCancellation?.abort(new Error('Managed profile startup cancelled by stop'));
            await this.#starting?.catch(() => {});
            await this.#detachBrowser();
            if (!this.#client) return false;
            if (this.#stopConfirmed) return true;
            try {
                if (await this.#client.stopProfile(this.profileId) === true) {
                    this.#stopConfirmed = true;
                    return true;
                }
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
        if (!this.#client) throw new Error('Profile deletion requires a bound REST controller');
        if (this.#recycling) throw new Error('Managed profile recycling has been requested');
        if (this.#deleted) return true;
        if (await this.stop() !== true) {
            throw cleanupError(this.profileId, 'stop-unconfirmed', 'Managed profile shutdown unconfirmed');
        }
        let cause;
        try {
            if (await this.#client.deleteProfile(this.profileId) === true) {
                this.#deleted = true;
                return true;
            }
        } catch (error) {
            cause = error;
        }
        throw cleanupError(this.profileId, 'delete-unconfirmed', 'Managed profile deletion unconfirmed', cause);
    }

    recycle() {
        this.#recycling ??= this.#recycle().finally(() => {
            if (!this.#recycleDispatched) this.#recycling = null;
        });
        return this.#recycling;
    }

    async #recycle() {
        if (!this.#client) throw new Error('Profile recycling requires a bound REST controller');
        if (typeof this.#client.recycleProfile !== 'function') throw new Error('Controller does not support profile recycling');
        if (this.#deleting || this.#deleted) throw new Error('Managed profile deletion has been requested');
        if (await this.stop() !== true) {
            throw cleanupError(this.profileId, 'stop-unconfirmed', 'Managed profile shutdown unconfirmed');
        }
        this.#recycleDispatched = true;
        let cause;
        try {
            if (await this.#client.recycleProfile(this.profileId) === true) return true;
        } catch (error) {
            cause = error;
        }
        throw cleanupError(this.profileId, 'recycle-unconfirmed', 'Managed profile recycling unconfirmed', cause);
    }
}

export async function rollbackNewManagedProfile(profile, cause, operation = 'delete') {
    const recycling = operation === 'recycle';
    let profileCleanup = recycling ? 'recycled' : 'deleted';
    try {
        if (recycling) await profile.recycle();
        else await profile.delete();
    } catch (error) {
        profileCleanup = error.profileCleanup ?? 'stop-unconfirmed';
    }
    logger.warn('Managed profile initialization failed', { profileId: profile.profileId, profileCleanup });
    return cleanupError(profile.profileId, profileCleanup, 'Managed profile initialization failed', cause);
}
