/**
 * GoLogin Profile Manager
 * إدارة بروفايلات GoLogin
 */

import { GologinApi } from 'gologin';
import logger from '../utils/logger.js';
import { requireControllerProfileId } from '../utils/controller-id.js';
import { GoLoginClient, getGoLoginApiKey, isGoLoginWriteRejected } from './client.js';
import config from '../config.js';

const launchTimeout = 120000;
const browserOperationTimeout = 10000;
const compensateFailedStart = Symbol('compensateFailedStart');
const internallyBoundSession = Symbol('internallyBoundSession');

function bindGoLoginSession() {
    const token = getGoLoginApiKey();
    return {
        [internallyBoundSession]: true,
        client: new GoLoginClient(token),
        createSdk: () => {
            try {
                return GologinApi({ token });
            } catch {
                throw new Error('Could not initialize GoLogin SDK');
            }
        }
    };
}

class GoLoginWaitError extends Error {}

function waitFor(pending, timeout, message, signal, onAbandon) {
    let timer;
    let onAbort;
    const deadline = new Promise((_, reject) => {
        const abandon = error => {
            onAbandon?.();
            reject(error);
        };
        onAbort = () => abandon(signal.reason);
        if (signal?.aborted) return onAbort();
        signal?.addEventListener('abort', onAbort, { once: true });
        timer = setTimeout(() => abandon(new GoLoginWaitError(message)), timeout);
    });
    return Promise.race([pending, deadline]).finally(() => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
    });
}

function cleanupError(profileId, profileCleanup, message, cause) {
    return Object.assign(new Error(message, { cause }), { profileId, profileCleanup });
}

class GoLoginProfile {
    #profileId;
    #gologinApi;
    #ownsSdk = false;
    #session;
    #startController;
    #starting;
    #launching;
    #ownedBrowser;
    #closing;
    #stopping;
    #stoppingSdk;
    #deleting;
    #deleteUnconfirmed = false;
    #deleted = false;
    #needsCleanup = false;
    #stopConfirmed = false;

    constructor(profileId, gologinApi = null, session = null) {
        this.#profileId = requireControllerProfileId(profileId);
        this.#gologinApi = gologinApi;
        this.#session = session;
        this.browser = null;
        this.page = null;
    }

    get profileId() {
        return this.#profileId;
    }

    get gologinApi() {
        return this.#gologinApi;
    }

    start() {
        if (this.#deleted || this.#deleting) return Promise.reject(new Error('GoLogin profile is being deleted or was deleted'));
        if (this.#deleteUnconfirmed) return Promise.reject(new Error('GoLogin profile deletion is unconfirmed'));
        if (this.#stopping) return Promise.reject(new Error('GoLogin profile shutdown is in progress'));
        if (this.#starting) return this.#starting;
        if (this.browser) return Promise.resolve(this);
        if (this.#needsCleanup || this.#launching || this.#stoppingSdk) {
            return Promise.reject(new Error('GoLogin profile shutdown is unconfirmed'));
        }

        try {
            if (!this.#gologinApi) this.#session ??= bindGoLoginSession();
        } catch (error) {
            return Promise.reject(error);
        }
        this.#startController = new AbortController();
        const { signal } = this.#startController;
        this.#starting = Promise.resolve().then(() => this.#startBrowser(signal)).finally(() => {
            this.#starting = null;
            this.#startController = null;
        });
        return this.#starting;
    }

    async #startBrowser(signal) {
        signal.throwIfAborted();
        try {
            if (!this.#gologinApi) {
                this.#gologinApi = this.#session.createSdk();
                this.#ownsSdk = this.#session[internallyBoundSession] === true;
            }

            const browser = await this.#launchBrowser(signal);
            signal.throwIfAborted();
            if (!browser) throw new GoLoginWaitError('GoLogin launch returned no browser');

            const creatingPage = Promise.resolve().then(() => {
                signal.throwIfAborted();
                return browser.newPage();
            });
            const page = await waitFor(creatingPage, browserOperationTimeout, 'GoLogin page creation timed out', signal);
            signal.throwIfAborted();
            if (!page) throw new GoLoginWaitError('GoLogin page creation returned no page');
            this.browser = browser;
            this.page = page;
            logger.info('GoLogin profile started', { profileId: this.profileId });
            return this;
        } catch (error) {
            // A pending launch retains ownership of its eventual handle. Shutdown takes over on cancellation.
            if (!this.#launching && !signal.aborted) await this.#closeBrowser();
            throw error instanceof GoLoginWaitError ? error : new Error('Could not initialize GoLogin browser');
        }
    }

    #launchBrowser(signal) {
        const launching = Promise.resolve().then(async () => {
            signal.throwIfAborted();
            this.#needsCleanup = true;
            this.#stopConfirmed = false;
            const result = await this.#gologinApi.launch({ profileId: String(this.profileId), cloud: true });
            this.#ownedBrowser = result?.browser;
            return this.#ownedBrowser;
        });
        this.#launching = launching;
        return waitFor(launching, launchTimeout, 'GoLogin browser launch timed out', signal, () => {
            if (this.#launching !== launching) return;
            // Keep shutdown ownership until the SDK call and the late cleanup both settle.
            this.#launching = launching.catch(() => {}).then(() => this.#stopBrowser()).then(stopped => {
                if (!stopped) logger.warn('GoLogin late launch cleanup is unconfirmed', { profileId: this.profileId });
                return stopped;
            }).catch(() => false).finally(() => {
                this.#launching = null;
            });
        }).finally(() => {
            if (this.#launching === launching) this.#launching = null;
        });
    }

    async getBrowser() {
        await this.start();
        return this.browser;
    }

    async getPage() {
        await this.start();
        return this.page;
    }

    #closeBrowser() {
        const browser = this.#ownedBrowser;
        if (!browser) return Promise.resolve(true);
        this.#closing ??= Promise.resolve().then(() => browser.close()).then(result => {
            if (result === false) return false;
            this.#ownedBrowser = null;
            if (!this.#ownsSdk || typeof this.#gologinApi?.stop !== 'function') this.#stopConfirmed = true;
            return true;
        }, () => false).finally(() => {
            this.#closing = null;
        });
        return waitFor(this.#closing, browserOperationTimeout, 'GoLogin browser close timed out').catch(() => false);
    }

    async #stopBrowser() {
        this.browser = null;
        this.page = null;
        if (!this.#needsCleanup) return this.#stopConfirmed;
        const closed = await this.#closeBrowser();
        if (this.#ownsSdk && !this.#stopConfirmed && typeof this.#gologinApi?.stop === 'function') {
            this.#stoppingSdk ??= Promise.resolve().then(() => this.#gologinApi.stop()).then(result => {
                this.#stopConfirmed = result !== false;
            }, () => {}).finally(() => {
                this.#stoppingSdk = null;
            });
            await waitFor(this.#stoppingSdk, browserOperationTimeout, 'GoLogin session stop timed out').catch(() => {});
        }
        if (!closed || !this.#stopConfirmed) return false;
        this.#needsCleanup = false;
        return true;
    }

    stop() {
        this.#stopping ??= Promise.resolve().then(async () => {
            this.#startController?.abort(new GoLoginWaitError('GoLogin startup interrupted by shutdown'));
            await this.#starting?.catch(() => {});
            const stopped = !this.#launching && await this.#stopBrowser();
            if (stopped) logger.info('GoLogin profile stopped', { profileId: this.profileId });
            else logger.warn('GoLogin session stop could not be confirmed', { profileId: this.profileId });
            return stopped;
        }).finally(() => {
            this.#stopping = null;
        });
        return this.#stopping;
    }

    delete(mode) {
        if (this.#deleted) return Promise.resolve(true);
        if (this.#deleting) return this.#deleting;
        if (this.#deleteUnconfirmed) {
            return Promise.reject(cleanupError(this.profileId, 'delete-unconfirmed', 'GoLogin profile deletion is unconfirmed'));
        }
        if (this.#gologinApi && !this.#session) {
            return Promise.reject(new Error('Deleting an externally managed GoLogin profile requires a bound REST credential'));
        }
        try {
            this.#session ??= bindGoLoginSession();
        } catch (error) {
            return Promise.reject(error);
        }
        this.#deleting = Promise.resolve().then(() => this.#deleteProfile(mode === compensateFailedStart)).finally(() => {
            this.#deleting = null;
        });
        return this.#deleting;
    }

    async #deleteProfile(compensate) {
        if (this.#starting || this.#needsCleanup) await this.stop();
        if (this.#needsCleanup) {
            if (compensate && this.#launching) {
                // The factory owns this allocation. Continue only after a confirmed stop and before any DELETE.
                void this.#launching.then(async stopped => {
                    if (stopped !== true) return;
                    await this.#deleting?.catch(() => {});
                    await this.delete();
                }).catch(error => {
                    logger.warn('GoLogin late launch profile deletion failed', {
                        profileId: this.profileId, profileCleanup: error.profileCleanup ?? 'delete-unconfirmed'
                    });
                });
            }
            throw cleanupError(this.profileId, 'stop-unconfirmed', 'GoLogin profile shutdown is unconfirmed');
        }
        let deleted;
        try {
            deleted = await this.#session.client.deleteProfile(this.profileId);
        } catch (error) {
            if (isGoLoginWriteRejected(error)) {
                throw cleanupError(this.profileId, 'delete-rejected', 'GoLogin profile deletion was rejected');
            }
        }
        if (deleted !== true) {
            this.#deleteUnconfirmed = true;
            throw cleanupError(this.profileId, 'delete-unconfirmed', 'GoLogin profile deletion is unconfirmed');
        }
        this.#deleted = true;
        logger.info('GoLogin profile deleted', { profileId: this.profileId });
        return true;
    }
}

/** Create and start a new GoLogin profile. */
export async function createAndStartProfile(name, proxy = null) {
    let profile;
    try {
        const session = bindGoLoginSession();
        const created = await session.client.createProfileWithProxy(name, proxy, config.app.testProxy !== false);
        profile = new GoLoginProfile(created.id, null, session);
        const { profileId } = profile;

        await new Promise(resolve => setTimeout(resolve, 5000));
        try {
            await session.client.getProfile(profileId);
        } catch {
            logger.warn('GoLogin profile lookup failed before startup', { profileId });
        }
        return await profile.start();
    } catch (error) {
        if (!profile) throw error;
        let profileCleanup = 'deleted';
        try {
            await profile.delete(compensateFailedStart);
        } catch (cleanup) {
            profileCleanup = cleanup.profileCleanup ?? 'stop-unconfirmed';
        }
        logger.error('GoLogin profile initialization failed', { profileId: profile.profileId, profileCleanup });
        throw cleanupError(profile.profileId, profileCleanup, 'GoLogin profile initialization failed', error);
    }
}

export default GoLoginProfile;
