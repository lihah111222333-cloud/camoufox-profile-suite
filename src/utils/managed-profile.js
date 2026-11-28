import { requireControllerProfileId } from './controller-id.js';
import { controllerRequestOutcomeUnconfirmed } from './controller-request.js';
import logger from './logger.js';

function cleanupError(profileId, profileCleanup, message, cause) {
    return Object.assign(new Error(message, { cause }), { profileId, profileCleanup });
}

class ManagedStartupCleanupError extends Error {
    constructor(profileId, cause) {
        super('Managed profile startup did not finish. Shutdown is unconfirmed.', { cause });
        this.profileId = profileId;
        this.profileCleanup = 'stop-unconfirmed';
    }
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
    #stopState = null;
    #deleted = false;
    #deleteUnconfirmed = false;
    #ownedPages = new Map();
    #openingPage = null;
    #borrowedPageCreationUnconfirmed = false;
    #borrowedCleanupBrowser = null;

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
        while (this.#stopping) {
            const stopped = await this.#stopping;
            signal?.throwIfAborted();
            if (this.#client && stopped !== true) {
                throw cleanupError(this.profileId, 'stop-unconfirmed', 'Managed profile shutdown unconfirmed');
            }
        }
        if (this.#deleted) throw new Error('Managed profile has been deleted');
        if (this.#deleting) throw new Error('Managed profile deletion is in progress');
        if (this.#deleteUnconfirmed) {
            throw cleanupError(this.profileId, 'delete-unconfirmed', 'Managed profile deletion unconfirmed');
        }
        if (this.#recycling) throw new Error('Managed profile recycling has been requested');
        if (this.#starting) return this.#starting;
        if (this.#stopState === 'unconfirmed') {
            throw cleanupError(this.profileId, 'stop-unconfirmed', 'Managed profile shutdown unconfirmed');
        }
        if (this.#borrowedPageCreationUnconfirmed) throw this.#borrowedPagesUnconfirmed();
        if (this.#borrowedCleanupBrowser) {
            if (this.#ownedPages.size && this.#borrowedCleanupBrowser.isConnected?.() === false) {
                throw this.#borrowedPagesUnconfirmed();
            }
            throw new Error('Borrowed browser cleanup is incomplete. Retry stop before reconnecting.');
        }
        if (this.browser) return this;

        const cancellation = new AbortController();
        const abort = () => cancellation.abort(signal.reason);
        let launchAcknowledged = false;
        let unconfirmedLaunch;
        const startProfile = this.#client && (async () => {
            try {
                // Await a dispatched launch even when the caller cancels the local attachment.
                const receipt = await this.#client.startProfile(this.profileId);
                launchAcknowledged = true;
                return receipt;
            } catch (error) {
                if (controllerRequestOutcomeUnconfirmed(error)) {
                    unconfirmedLaunch = error;
                    cancellation.abort(error);
                }
                throw error;
            }
        });
        signal?.addEventListener('abort', abort, { once: true });
        this.#startCancellation = cancellation;
        this.#starting = Promise.resolve().then(async () => {
            cancellation.signal.throwIfAborted();
            this.#stopState = null;
            const profile = await this.#startBrowser(startProfile, this.#borrowedAddress, cancellation.signal);
            cancellation.signal.throwIfAborted();
            return profile;
        }).catch(async error => {
            await this.#detachBrowser(error);
            if (unconfirmedLaunch || (launchAcknowledged && signal?.aborted)) {
                this.#stopState = 'unconfirmed';
                throw new ManagedStartupCleanupError(this.profileId, unconfirmedLaunch ?? error);
            }
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
        const browser = this.browser;
        if (this.#borrowedAddress && (!browser || browser.isConnected?.() === false)) {
            throw new Error('Borrowed browser connection is unavailable');
        }
        return browser;
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
        if (this.page.isClosed()) throw new Error('Managed page is unavailable because it has been closed');
        return this.page;
    }

    async createOwnedPage() {
        const browser = this.browser;
        if (this.#borrowedPageCreationUnconfirmed) throw this.#borrowedPagesUnconfirmed();
        if (!browser) throw new Error('Managed browser is unavailable');
        this.#openingPage ??= Promise.resolve().then(async () => {
            if (!this.#client && browser.isConnected?.() === false) {
                throw new Error('Borrowed browser connection is unavailable');
            }
            let page;
            try {
                page = await browser.newPage();
                if (!page) throw new Error('Managed browser did not return a page');
            } catch (error) {
                if (this.#client) throw error;
                // A failed page request can leave a tab without a handle or a known target ID.
                this.#borrowedPageCreationUnconfirmed = true;
                throw this.#borrowedPagesUnconfirmed(error);
            }

            this.#ownedPages.set(page, null);
            if (!this.#client) {
                try {
                    // Capture the Chromium target ID from this page's Puppeteer target while attached.
                    const targetId = page.target?.()?._targetId;
                    if (typeof targetId === 'string' && /^[a-f0-9]{32}$/i.test(targetId)) {
                        this.#ownedPages.set(page, targetId);
                    }
                } catch {
                    // Retain page ownership even when target metadata is unavailable.
                }
            }
            return page;
        }).finally(() => {
            this.#openingPage = null;
        });
        return this.#openingPage;
    }

    #borrowedPagesUnconfirmed(cause) {
        return Object.assign(cleanupError(
            this.profileId, 'stop-unconfirmed',
            this.#borrowedPageCreationUnconfirmed
                ? 'Borrowed browser page creation is unconfirmed. Check the original browser.'
                : 'Borrowed browser disconnected with managed pages pending cleanup. Check the original browser.',
            cause
        ), {
            targetIds: [...this.#ownedPages.values()].filter(Boolean),
            unresolvedPageCount: this.#ownedPages.size + Number(this.#borrowedPageCreationUnconfirmed)
        });
    }

    async #detachBrowser(cause) {
        const browser = this.#borrowedCleanupBrowser ?? this.browser;
        this.browser = null;
        this.page = null;
        this[this.#addressField] = null;

        await this.#openingPage?.catch(() => {});
        for (const page of this.#ownedPages.keys()) {
            try {
                if (!page.isClosed()) {
                    if (!this.#client && browser?.isConnected?.() === false) continue;
                    await page.close();
                }
                this.#ownedPages.delete(page);
            } catch {
                logger.warn('Could not close a page opened by the profile manager', { profileId: this.profileId });
            }
        }
        if (!this.#client) {
            this.#borrowedCleanupBrowser = browser;
            if (this.#ownedPages.size) {
                if (this.#borrowedPageCreationUnconfirmed || browser?.isConnected?.() === false) {
                    throw this.#borrowedPagesUnconfirmed(cause);
                }
                return;
            }
        }
        this.#ownedPages.clear();

        try {
            await browser?.disconnect();
            this.#borrowedCleanupBrowser = null;
        } catch {
            logger.warn('Could not detach the managed browser connection', { profileId: this.profileId });
        }
        if (this.#borrowedPageCreationUnconfirmed) throw this.#borrowedPagesUnconfirmed(cause);
    }

    stop() {
        this.#stopping ??= Promise.resolve().then(async () => {
            this.#startCancellation?.abort(new Error('Managed profile startup cancelled by stop'));
            await this.#starting?.catch(() => {});
            await this.#detachBrowser();
            if (!this.#client) return false;
            if (this.#stopState === 'confirmed') return true;
            this.#stopState = 'unconfirmed';
            try {
                if (await this.#client.stopProfile(this.profileId) === true) {
                    this.#stopState = 'confirmed';
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

    async #stopBeforeCleanup() {
        // An earlier stop cannot attest to the state of a browser reopened by another operator.
        if (this.#stopState === 'confirmed') {
            throw cleanupError(this.profileId, 'stop-unconfirmed', 'Managed profile shutdown confirmation is stale. Check the profile in its controller.');
        }
        if (await this.stop() !== true) {
            throw cleanupError(this.profileId, 'stop-unconfirmed', 'Managed profile shutdown unconfirmed');
        }
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
        if (this.#deleteUnconfirmed) {
            throw cleanupError(this.profileId, 'delete-unconfirmed', 'Managed profile deletion unconfirmed');
        }
        await this.#stopBeforeCleanup();
        let cause;
        try {
            if (await this.#client.deleteProfile(this.profileId) === true) {
                this.#deleted = true;
                return true;
            }
        } catch (error) {
            cause = error;
        }
        this.#deleteUnconfirmed = true;
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
        await this.#stopBeforeCleanup();
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
    const startupCause = cause instanceof ManagedStartupCleanupError ? cause.cause : cause;
    return cleanupError(profile.profileId, profileCleanup, 'Managed profile initialization failed', startupCause);
}
