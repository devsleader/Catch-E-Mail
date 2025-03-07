import dns from 'dns/promises';

export const validateInputEmail = (reqBody) => {
    if (!reqBody || typeof reqBody !== 'object' || Array.isArray(reqBody)) {
        const error = new Error('Request body must be a single JSON object.');
        error.step = 'inputValidation';
        throw error;
    }

    const { email } = reqBody;

    if (!email || typeof email !== 'string' || !email.trim()) {
        const error = new Error('A valid email is required.');
        error.step = 'inputValidation';
        throw error;
    }

    if (email.includes(',') || email.includes(';') || email.trim().split(/\s+/).length > 1) {
        const error = new Error('Only a single email address is allowed.');
        error.step = 'inputValidation';
        throw error;
    }

    return email.trim();
};

export const validateEmailFormat = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {
        const error = new Error('Invalid email format.');
        error.step = 'syntaxValidation';
        throw error;
    }
};

export const validateDnsRecords = async (domain) => {
    try {
        const addresses = await dns.resolve(domain, 'A');
        if (!addresses.length) {
            const error = new Error('Domain does not resolve to any IP address.');
            error.step = 'dnsValidation';
            throw error;
        }
    } catch (err) {
        const error = new Error(`DNS resolution failed: ${err.message}`);
        error.step = 'dnsValidation';
        throw error;
    }
};

export const validateMxRecords = async (domain) => {
    try {
        const mxRecords = await dns.resolveMx(domain);
        const validMx = mxRecords.filter(record => record.exchange && record.exchange.trim());
        if (!validMx.length) {
            const error = new Error('No valid MX records found for the domain.');
            error.step = 'mxValidation';
            throw error;
        }
    } catch (err) {
        const error = new Error(`MX records validation failed: ${err.message}`);
        error.step = 'mxValidation';
        throw error;
    }
};