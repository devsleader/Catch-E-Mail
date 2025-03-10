import validator from 'validator';
import dns from 'dns/promises';
import { verifyEmail } from '@devmehq/email-validator-js';

export const validateInputEmail = (reqBody) => {
    if (!reqBody || typeof reqBody !== 'object' || Array.isArray(reqBody)) {
        const error = new Error('Email failed to pass input validation test.');
        error.step = 'inputValidation';
        throw error;
    }
    const { email } = reqBody;
    if (!email || typeof email !== 'string' || !email.trim()) {
        const error = new Error('Email failed to pass input validation test.');
        error.step = 'inputValidation';
        throw error;
    }
    if (email.includes(',') || email.includes(';') || email.trim().split(/\s+/).length > 1) {
        const error = new Error('Email failed to pass input validation test.');
        error.step = 'inputValidation';
        throw error;
    }
    return email.trim();
};

export const validateEmailFormat = (email) => {
    if (!validator.isEmail(email)) {
        const error = new Error('Email failed to pass syntax validation test.');
        error.step = 'syntaxValidation';
        throw error;
    }
};

export const validateDnsRecords = async (domain) => {
    try {
        const addresses = await dns.resolve(domain, 'A');
        if (!addresses.length) {
            const error = new Error('Email failed to pass dns record validation test.');
            error.step = 'dnsValidation';
            throw error;
        }
    } catch (err) {
        const error = new Error('Email failed to pass dns record validation test.');
        error.step = 'dnsValidation';
        throw error;
    }
};

export const validateMxRecords = async (domain) => {
    try {
        const mxRecords = await dns.resolveMx(domain);
        const validMx = mxRecords.filter(record => record.exchange && record.exchange.trim());
        if (!validMx.length) {
            const error = new Error('Email failed to pass mx record validation test.');
            error.step = 'mxValidation';
            throw error;
        }
    } catch (err) {
        const error = new Error('Email failed to pass mx record validation test.');
        error.step = 'mxValidation';
        throw error;
    }
};

export const validateSMTPConnection = async (email) => {
    const result = await verifyEmail({
        emailAddress: email,
        verifySmtp: true,
        timeout: 3000,
    });
    if (result.validSmtp !== true) {
        const error = new Error('Email failed to pass smtp validation test.');
        error.step = 'smtpValidation';
        throw error;
    }
    return result; 
};