export function requireControllerProfileId(profileId) {
    if (Number.isSafeInteger(profileId) && profileId >= 0) return profileId;
    if (typeof profileId !== 'string' || !profileId || /[^A-Za-z0-9_-]/.test(profileId)) {
        throw new Error('Invalid browser controller profile ID');
    }
    return profileId;
}

export function profileIdPathComponent(profileId) {
    return encodeURIComponent(requireControllerProfileId(profileId));
}
